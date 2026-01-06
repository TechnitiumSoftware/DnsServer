using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace ProxmoxAutodiscovery;

internal sealed class PveApi
{
    private readonly HttpClient _client;
    
    public PveApi(
        Uri baseUri,
        string accessToken,
        bool disableSslValidation,
        TimeSpan timeout,
        IWebProxy proxy)
    {
        var handler = new HttpClientHandler
        {
            Proxy = proxy
        };
        
        if (disableSslValidation)
            handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        
        _client = new HttpClient(handler)
        {
            BaseAddress = baseUri,
            Timeout =  timeout
        };

        _client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", $"PVEAPIToken={accessToken}");
    }

    private static T[] DataOrDefault<T>(PveResponse<T[]>? response)
    {
        return response is { Data: not null } 
            ? response.Data 
            : [];
    }

    public async Task<ProxmoxNode[]> GetNodesAsync(CancellationToken cancellationToken)
    {
        const string url = "api2/json/nodes";
        var response = await _client.GetFromJsonAsync<PveResponse<ProxmoxNode[]>>(url, cancellationToken);
        return DataOrDefault(response);
    }

    public async Task<VmDescription[]> GetLxcsAsync(string node, CancellationToken cancellationToken)
    {
        var url = $"api2/json/nodes/{node}/lxc";
        var response = await _client.GetFromJsonAsync<PveResponse<VmDescription[]>>(url, cancellationToken);
        return DataOrDefault(response);
    }
    
    public async Task<VmNetworkInterface[]> GetLxcIpAddressesAsync(string node, long vmId, CancellationToken cancellationToken)
    {
        var url = $"api2/json/nodes/{node}/lxc/{vmId}/interfaces";
        var response = await _client.GetFromJsonAsync<PveResponse<VmNetworkInterface[]>>(url, cancellationToken);
        return DataOrDefault(response);
    }
    
    public async Task<VmDescription[]> GetQemusAsync(string node, CancellationToken cancellationToken)
    {
        var url = $"api2/json/nodes/{node}/qemu";
        var response = await _client.GetFromJsonAsync<PveResponse<VmDescription[]>>(url, cancellationToken);
        
        var result = DataOrDefault(response);
        foreach (var vmDescription in result)
        {
            vmDescription.Type = "qemu";
        }
        
        return result;
    }

    public async Task<VmNetworkInterface[]> GetQemuIpAddressesAsync(string node, long vmId, CancellationToken cancellationToken)
    {
        try
        {
            var url = $"api2/json/nodes/{node}/qemu/{vmId}/agent/network-get-interfaces";
            // Actually, QEMU Agents api and LXC api have slightly different models for network interface ips
            // But we can safely ignore it as long as we use only ip-address property
            var response = await _client.GetFromJsonAsync<PveResponse<QemuAgentResponse<VmNetworkInterface[]>>>(url, cancellationToken);
            if (response is { Data.Result: not null })
                return response.Data.Result;

            return [];
        }
        catch (HttpRequestException) // QEMU Guest Agent probably not installed
        {
            return [];
        }
    }
}

public sealed class PveResponse<T>
{
    [JsonPropertyName("data")]
    public T Data { get; set; }
}

public sealed class ProxmoxNode
{
    [JsonPropertyName("node")]
    public string Node { get; set; }
}

public sealed class VmDescription
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

public sealed class QemuAgentResponse<T>
{
    [JsonPropertyName("result")]
    public T Result { get; set; }
}

public sealed class VmNetworkInterface
{
    [JsonPropertyName("name")]
    public string Name { get; set; }
    
    [JsonPropertyName("ip-addresses")]
    public VmIpAddress[] IpAddresses { get; set; }
}

public sealed class VmIpAddress
{
    [JsonPropertyName("ip-address")]
    public string Address { get; set; }
}
