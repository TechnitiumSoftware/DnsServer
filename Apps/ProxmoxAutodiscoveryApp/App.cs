/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using DnsServerCore.ApplicationCommon;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace ProxmoxAutodiscovery
{
    public sealed class App : IDnsApplication, IDnsAppRecordRequestHandler
    {
        private static readonly JsonSerializerOptions SerializerOptions = new()
        {
            WriteIndented = true,
            Converters =
            {
                new IpNetworkConverter()
            }
        };
        
        private IDnsServer _dnsServer;

        private AppConfiguration _appConfig;
        private PveService _pveService;
        private IReadOnlyDictionary<string, DiscoveredVm> _autodiscoveryData = new Dictionary<string, DiscoveredVm>(StringComparer.OrdinalIgnoreCase);
        
        private CancellationTokenSource _cts = new();

        private Task _updateLoop = Task.CompletedTask;

        #region Dispose
        
        public void Dispose()
        {
            _cts.Cancel();
            _updateLoop.GetAwaiter().GetResult();
        }
        
        #endregion

        #region Public
        
        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;
            
            _appConfig = JsonSerializer.Deserialize<AppConfiguration>(config);

            _pveService = new PveService(new PveApi(
                _appConfig.ProxmoxHost,
                _appConfig.AccessToken,
                _appConfig.DisableSslValidation,
                TimeSpan.FromSeconds(_appConfig.TimeoutSeconds),
                _dnsServer.Proxy
            ));

            try
            {
                _autodiscoveryData = await _pveService.DiscoverVmsAsync(CancellationToken.None);
                _dnsServer.WriteLog("Successfully initialized ProxmoxAutodiscoveryApp");
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog(ex);
            }

            _cts = new CancellationTokenSource();
            _updateLoop = UpdateLoop();
        }

        public Task<DnsDatagram> ProcessRequestAsync(
            DnsDatagram request,
            IPEndPoint remoteEP,
            DnsTransportProtocol protocol,
            bool isRecursionAllowed,
            string zoneName,
            string appRecordName,
            uint appRecordTtl,
            string appRecordData)
        {
            try
            {
                var question = request.Question[0];

                if (question is not { Type: DnsResourceRecordType.A or DnsResourceRecordType.AAAA })
                    return Task.FromResult<DnsDatagram>(null);

                if (!TryGetHostname(question.Name, appRecordName, out var hostname))
                    return Task.FromResult<DnsDatagram>(null);

                if (!_autodiscoveryData.TryGetValue(hostname, out var vm))
                    return Task.FromResult<DnsDatagram>(null);
                
                var recordConfig = JsonSerializer.Deserialize<AppRecordConfig>(appRecordData, SerializerOptions);

                if (!IsVmMatchFilters(vm, recordConfig.Type, recordConfig.Tags ?? []))
                    return Task.FromResult<DnsDatagram>(null);
                
                var isIpv6 = question.Type == DnsResourceRecordType.AAAA;

                var answer = GetMatchingIps(
                        vm.Addresses,
                        recordConfig.Cidr,
                        isIpv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork)
                    .Select(x => new DnsResourceRecord(
                        question.Name,
                        question.Type,
                        DnsClass.IN,
                        appRecordTtl,
                        isIpv6
                            ? new DnsAAAARecordData(x)
                            : new DnsARecordData(x)
                    )).ToList();
                
                var data = new DnsDatagram(
                    request.Identifier,
                    true,
                    request.OPCODE,
                    true,
                    false,
                    request.RecursionDesired,
                    isRecursionAllowed,
                    false,
                    false,
                    DnsResponseCode.NoError,
                    request.Question,
                    answer: answer);

                return Task.FromResult(data);
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog(ex);
                return Task.FromResult<DnsDatagram>(null);
            }
        }

        #endregion

        #region Private

        private async Task UpdateLoop()
        {
            while (!_cts.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(_appConfig.PeriodSeconds * 1000, _cts.Token);
                    if (_appConfig.Enabled)
                        _autodiscoveryData = await _pveService.DiscoverVmsAsync(_cts.Token);
                }
                catch (OperationCanceledException oce) when (oce.CancellationToken == _cts.Token)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog(ex);
                }
            }
        }

        private static bool TryGetHostname(string qname, string appRecordName, out string hostname)
        {
            var query = qname.ToLowerInvariant();
            var postfix = $".{appRecordName}".ToLowerInvariant();
            // qname must be {hostname}.{appRecordName}

            if (query.EndsWith(postfix))
            {
                hostname = qname.Substring(0, qname.Length - postfix.Length);

                if (hostname.Contains('.'))
                {
                    hostname = null;
                    return false;
                }
                
                return true;
            }

            hostname = null;
            return false;
        }
        
        private static bool IsVmMatchFilters(DiscoveredVm network, string type, string[] tags)
        {
            if (type != null && network.Type != type)
                return false;
            
            if (tags.Length > 0 && !tags.All(x => network.Tags.Contains(x)))
                return false;

            return true;
        }

        private static IEnumerable<IPAddress> GetMatchingIps(IPAddress[] vmAddresses, IPNetwork[] allowedNetworks, AddressFamily addressFamily)
        {
            return vmAddresses
                .Where(x => x.AddressFamily == addressFamily)
                .Where(ip => allowedNetworks.Any(net => net.Contains(ip)));
        }

        #endregion

        #region Helper Classes

        private sealed class AppRecordConfig
        {
            [JsonPropertyName("type")]
            public string Type { get; set; }
            
            [JsonPropertyName("tags")]
            public string[] Tags { get; set; }
            
            [JsonPropertyName("cidr")]
            public IPNetwork[] Cidr { get; set; }
        }
        
        private sealed class IpNetworkConverter : JsonConverter<IPNetwork>
        {
            public override IPNetwork Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            {
                var str = reader.GetString();
                if (!string.IsNullOrEmpty(str))
                    return IPNetwork.Parse(str);

                return default;
            }

            public override void Write(Utf8JsonWriter writer, IPNetwork value, JsonSerializerOptions options)
            {
                writer.WriteStringValue(value.ToString());
            }
        }

        #endregion
        
        #region Properties

        public string Description => "Allows configuring autodiscovery for Proxmox QEMUs and LXCs based on a set of filters.";
        
        public string ApplicationRecordDataTemplate =>
            """
            {
                "type": "qemu",
                "tags": [
                    "autodiscovery"
                ],
                "cidr": [
                    "10.0.0.0/8,
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "fc00::/7"
                ]
            }
            """;

        #endregion
    }
}
