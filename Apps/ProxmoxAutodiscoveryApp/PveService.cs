using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace ProxmoxAutodiscovery;

internal sealed class PveService
{
    private readonly PveApi _api;

    public PveService(PveApi api)
    {
        _api = api;
    }

    public async Task<IReadOnlyDictionary<string, DiscoveredVm>> DiscoverVmsAsync(CancellationToken cancellationToken)
    {
        var nodes = await _api.GetNodesAsync(cancellationToken);

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
        var qemus = await _api.GetQemusAsync(node, cancellationToken);
        var result = new List<DiscoveredVm>(qemus.Length);

        foreach (var qemu in qemus)
        {
            var interfaces = await _api.GetQemuIpAddressesAsync(node, qemu.VmId, cancellationToken);
            result.Add(Map(qemu, interfaces));
        }
        
        return result;
    }

    private async Task<List<DiscoveredVm>> GetLxcVmNetworks(string node, CancellationToken cancellationToken)
    {
        var lxcs = await _api.GetLxcsAsync(node, cancellationToken);
        var result = new List<DiscoveredVm>(lxcs.Length);
        
        foreach (var lxc in lxcs)
        {
            var interfaces = await _api.GetLxcIpAddressesAsync(node, lxc.VmId, cancellationToken);
            result.Add(Map(lxc, interfaces));
        }

        return result;
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
}

public sealed record DiscoveredVm(string Name, string Type, string[] Tags, IPAddress[] Addresses)
{
    public override string ToString()
    {
        var tags = string.Join(";", Tags);
        var ips = string.Join<IPAddress>(", ", Addresses);
        return $"{Name} - type: {Type} tags: {tags} ips: [{ips}])";
    }
}
