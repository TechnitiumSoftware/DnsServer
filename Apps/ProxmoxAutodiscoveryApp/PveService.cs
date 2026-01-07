using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace ProxmoxAutodiscovery;

internal sealed class PveService
{
    private readonly HttpClient _client;

    public PveService(Uri baseUri,
        string accessToken,
        bool disableSslValidation,
        TimeSpan timeout,
        IWebProxy proxy)
    {
        var handler = new HttpClientHandler { Proxy = proxy };
        
        if (disableSslValidation)
            handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        
        _client = new HttpClient(handler)
        {
            BaseAddress = baseUri,
            Timeout =  timeout
        };

        _client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", $"PVEAPIToken={accessToken}");
    }

    public async Task<IReadOnlyDictionary<string, DiscoveredVm>> DiscoverVmsAsync(CancellationToken cancellationToken)
    {
        var nodes = await GetProxmoxDataAsync<ProxmoxNode[]>("api2/json/nodes", [], cancellationToken);

        var results = await Task
            .WhenAll(nodes.Select(x => GetVmNetworksAsync(x.Node, cancellationToken)));
        
        return results
            .SelectMany(x => x)
            .ToDictionary(
                x => x.Name,
                x => x,
                StringComparer.OrdinalIgnoreCase);
    }

    private async Task<IEnumerable<DiscoveredVm>> GetVmNetworksAsync(string node, CancellationToken cancellationToken)
    {
        var qemus = GetQemuVmNetworksAsync(node, cancellationToken);
        var lxcs = GetLxcVmNetworks(node, cancellationToken);
        
        var result = await Task.WhenAll(lxcs, qemus);
        return result.SelectMany(x => x);
    }

    private async Task<List<DiscoveredVm>> GetQemuVmNetworksAsync(string node, CancellationToken cancellationToken)
    {
        var result = new List<DiscoveredVm>();
        var qemus = await GetProxmoxDataAsync<VmDescription[]>(
            $"api2/json/nodes/{node}/qemu",
            [],
            cancellationToken);

        foreach (var qemu in qemus)
        {
            var agentResponse = await GetProxmoxDataAsync(
                $"api2/json/nodes/{node}/qemu/{qemu.VmId}/agent/network-get-interfaces",
                new QemuAgentResponse<VmNetworkInterface[]>{ Result = [] },
                cancellationToken);
                
            result.Add(Map(qemu, agentResponse.Result));
        }
        
        return result;
    }

    private async Task<List<DiscoveredVm>> GetLxcVmNetworks(string node, CancellationToken cancellationToken)
    {
        var lxcs = await GetProxmoxDataAsync<VmDescription[]>(
            $"api2/json/nodes/{node}/lxc",
            [],
            cancellationToken);
        var result = new List<DiscoveredVm>(lxcs.Length);
        
        foreach (var lxc in lxcs)
        {
            var interfaces = await GetProxmoxDataAsync<VmNetworkInterface[]>(
                $"api2/json/nodes/{node}/lxc/{lxc.VmId}/interfaces",
                [],
                cancellationToken);
            result.Add(Map(lxc, interfaces));
        }

        return result;
    }

    private async Task<T> GetProxmoxDataAsync<T>(string url, T defaultValue, CancellationToken cancellationToken)
    {
        var response = await _client.GetFromJsonAsync<PveResponse<T>>(url, cancellationToken);
        return response is { Data: not null } 
            ? response.Data 
            : defaultValue;
    }

    private static DiscoveredVm Map(VmDescription vm, VmNetworkInterface[] interfaces)
    {
        return new DiscoveredVm(
            Name: vm.Name,
            Type: vm.Type,
            Tags: vm.Tags.ToLowerInvariant().Split(';'),
            Addresses: interfaces
                .Where(x => x.Name != "lo") // always excluding loopback interface
                .SelectMany(x => x.IpAddresses)
                .Select(x => IPAddress.Parse(x.Address))
                .ToArray());
    }

    #region DTOs

    private sealed class PveResponse<T>
    {
        [JsonPropertyName("data")]
        public T Data { get; set; }
    }

    private sealed class ProxmoxNode
    {
        [JsonPropertyName("node")]
        public string Node { get; set; }
    }

    private sealed class VmDescription
    {
        [JsonPropertyName("vmid")]
        public long VmId { get; set; }
     
        [JsonPropertyName("name")]
        public string Name { get; set; }
    
        [JsonPropertyName("tags")]
        public string Tags { get; set; }
    
        [JsonPropertyName("type")]
        public string Type { get; set; }
    }

    private sealed class QemuAgentResponse<T>
    {
        [JsonPropertyName("result")]
        public T Result { get; set; }
    }

    private sealed class VmNetworkInterface
    {
        [JsonPropertyName("name")]
        public string Name { get; set; }
    
        [JsonPropertyName("ip-addresses")]
        public VmIpAddress[] IpAddresses { get; set; }
    }

    private sealed class VmIpAddress
    {
        [JsonPropertyName("ip-address")]
        public string Address { get; set; }
    }

    #endregion
}

public sealed record DiscoveredVm(string Name, string Type, string[] Tags, IPAddress[] Addresses);
