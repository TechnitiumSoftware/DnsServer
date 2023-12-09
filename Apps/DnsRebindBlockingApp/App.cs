using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using DnsServerCore.ApplicationCommon;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsRebindBlocking
{
    public class App: IDnsApplication, IDnsPostProcessor
    {
        private AppConfig Config = null!;
        private HashSet<NetworkAddress> PrivateNetworks = new();
        private IDnsServer DnsServer = null!;
        
        public void Dispose()
        {
            // Nothing to dispose of.
        }

        public Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            DnsServer = dnsServer;
            Config = JsonSerializer.Deserialize<AppConfig>(config, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            })!;
            DnsServer.WriteLog($"Initializing. Enabled: {Config.Enabled}");
            PrivateNetworks.Clear();
            foreach (var privateNetwork in Config.PrivateNetworks)
            {
                var success = NetworkAddress.TryParse(privateNetwork, out NetworkAddress networkAddress);
                PrivateNetworks.Add(networkAddress);
            }

            // Add the ServerDomain to the PrivateDomains list so it doesn't block it's own.
            Config.PrivateDomains.Add(DnsServer.ServerDomain);

            return Task.CompletedTask;
        }

        public string Description => "Block DNS responses with protected IP ranges to prevent DNS rebinding attacks.";

        public Task<DnsDatagram> PostProcessAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            if (!Config.Enabled)
                return Task.FromResult(response);
            
            var answers = response.Answer.Where(res => !IsFilteredRebind(res)).ToList();
            var additional = response.Additional.Where(res => !IsFilteredRebind(res)).ToList();
            
            return Task.FromResult(response.Clone(answers, response.Authority, additional));
        }

        private bool IsFilteredRebind(DnsResourceRecord record)
        {
            if (record.Type != DnsResourceRecordType.A && record.Type != DnsResourceRecordType.AAAA)
                return false;
            IPAddress address;
            switch (record.Type)
            {
                case DnsResourceRecordType.A:
                    address = ((DnsARecordData)record.RDATA).Address;
                    break;
                case DnsResourceRecordType.AAAA:
                    address = ((DnsAAAARecordData)record.RDATA).Address;
                    break;
                default:
                    return false;
            }

            var isPrivateNetwork = PrivateNetworks.Any(net => net.Contains(address));
            var isPrivateDomain = IsZoneFound(Config.PrivateDomains, record.Name, out _);
            return isPrivateNetwork && !isPrivateDomain;
        }
        
        private static string? GetParentZone(string domain)
        {
            var i = domain.IndexOf('.');
            //dont return root zone
            return i > -1 ? domain[(i + 1)..] : null;
        }

        private static bool IsZoneFound(IReadOnlySet<string> domains, string domain, out string? foundZone)
        {
            var currentDomain = domain.ToLower();
            do
            {
                if (domains.Contains(currentDomain))
                {
                    foundZone = currentDomain;
                    return true;
                }

                currentDomain = GetParentZone(currentDomain);
            }
            while (currentDomain is not null);

            foundZone = null;
            return false;
        }
    }
}