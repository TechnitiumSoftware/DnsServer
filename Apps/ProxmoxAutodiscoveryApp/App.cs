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
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
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
        #region variables

        private static readonly JsonSerializerOptions SerializerOptions = new()
        {
            Converters =
            {
                new IpNetworkConverter()
            }
        };
        
        private IDnsServer _dnsServer;
        
        private PveService _pveService;
        private IReadOnlyDictionary<string, DiscoveredVm> _autodiscoveryData = new Dictionary<string, DiscoveredVm>(StringComparer.OrdinalIgnoreCase);
        
        private CancellationTokenSource _cts;
        private Task _backgroundUpdateLoopTask;

        #endregion
        
        #region IDisposable
        
        public void Dispose()
        {
            if (_cts is { IsCancellationRequested: false } && _backgroundUpdateLoopTask?.IsCompleted == false)
            {
                _cts.Cancel();
                _backgroundUpdateLoopTask.GetAwaiter().GetResult();
                _cts.Dispose();
            }
        }
        
        #endregion

        #region public
        
        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _dnsServer = dnsServer;
            
            var appConfig = JsonSerializer.Deserialize<AppConfig>(config);
            Validator.ValidateObject(appConfig, new ValidationContext(appConfig), validateAllProperties: true);

            _pveService = new PveService(
                appConfig.ProxmoxHost,
                appConfig.AccessToken,
                appConfig.DisableSslValidation,
                TimeSpan.FromSeconds(appConfig.TimeoutSeconds),
                _dnsServer.Proxy
            );

            try
            {
                if (_cts is { IsCancellationRequested: false } && _backgroundUpdateLoopTask?.IsCompleted == false)
                {
                    await _cts.CancelAsync();
                    await _backgroundUpdateLoopTask;
                    _cts.Dispose();
                }
                
                if (appConfig.Enabled)
                {
                    _autodiscoveryData = await _pveService.DiscoverVmsAsync(CancellationToken.None);
                    _dnsServer.WriteLog("Successfully initialized autodiscovery cache");
                    
                    _cts = new CancellationTokenSource();
                    _backgroundUpdateLoopTask = BackgroundUpdateLoop(TimeSpan.FromSeconds(appConfig.UpdateIntervalSeconds));
                }
            }
            catch (Exception ex)
            {
                _dnsServer.WriteLog("Error while initializing autodiscovery cache");
                _dnsServer.WriteLog(ex);
            }
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
            var question = request.Question[0];

            if (question is not { Type: DnsResourceRecordType.A or DnsResourceRecordType.AAAA })
                return Task.FromResult<DnsDatagram>(null);

            if (!TryGetHostname(question.Name, appRecordName, out var hostname))
                return Task.FromResult<DnsDatagram>(null);

            if (!_autodiscoveryData.TryGetValue(hostname, out var vm))
                return Task.FromResult<DnsDatagram>(null);
            
            var recordConfig = JsonSerializer.Deserialize<AppRecordConfig>(appRecordData, SerializerOptions);
            Validator.ValidateObject(recordConfig, new ValidationContext(recordConfig), validateAllProperties: true);
            
            if (!IsVmMatchFilters(vm, recordConfig.Type, recordConfig.Tags))
                return Task.FromResult<DnsDatagram>(null);
            
            var isIpv6 = question.Type == DnsResourceRecordType.AAAA;

            var answer = GetMatchingIps(
                    vm.Addresses,
                    recordConfig.Networks,
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

        #endregion

        #region private

        private async Task BackgroundUpdateLoop(TimeSpan updateInterval)
        {
            _dnsServer.WriteLog("Starting background data update loop.");
            
            using var pt = new PeriodicTimer(updateInterval);
            try
            {
                while (await pt.WaitForNextTickAsync(_cts.Token))
                {
                    try
                    {
                        _autodiscoveryData = await _pveService.DiscoverVmsAsync(_cts.Token);
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.WriteLog("Unexpected error while updating Proxmox data in background.");
                        _dnsServer.WriteLog(ex);
                    }
                }
            }
            catch (OperationCanceledException oce) when (oce.CancellationToken == _cts.Token)
            {
                // To simplify calling code, on cancellation we're just completing the task and exiting the loop
            }
        }
        
        private static bool TryGetHostname(string qname, string appRecordName, out string hostname)
        {
            hostname = null;
            
            var query = qname.ToLowerInvariant();

            if (query.Length <= appRecordName.Length)
                return false;

            if (!query.EndsWith(appRecordName))
                return false;

            if (query[^(appRecordName.Length + 1)] != '.')
                return false;
            
            hostname = qname.Substring(0, qname.Length - appRecordName.Length - 1);

            if (hostname.Contains('.'))
            {
                hostname = null;
                return false;
            }

            return true;
        }
        
        private static bool IsVmMatchFilters(DiscoveredVm network, string type, Filter<string> tagFilter)
        {
            // If type is specified, and it's not matching VM type - do not discover this host
            if (type != null && network.Type != type)
                return false;
            
            // If allowed tags are specified, VM must have all tags in the list to be discovered
            if (tagFilter.Allowed.Length > 0 && !tagFilter.Allowed.All(x => network.Tags.Contains(x)))
                return false;
            
            // If excluded tags are specified, VM must have no tags from the list to be discovered
            if (tagFilter.Excluded.Length > 0 && tagFilter.Excluded.Any(x => network.Tags.Contains(x)))
                return false;

            return true;
        }

        private static IEnumerable<IPAddress> GetMatchingIps(
            IPAddress[] vmAddresses,
            Filter<IPNetwork> networkFilter,
            AddressFamily addressFamily)
        {
            return vmAddresses
                // Picking only IPv4 or IPv6 addresses
                .Where(x => x.AddressFamily == addressFamily)
                // IP address must be in one of the allowed networks
                .Where(ip => networkFilter.Allowed.Any(net => net.Contains(ip)))
                // IP address must be in none of the blocked networks
                .Where(ip => networkFilter.Excluded.All(net => !net.Contains(ip)));
        }

        #endregion
        
        #region properties

        public string Description
            { get { return "Allows configuring autodiscovery for Proxmox QEMUs and LXCs based on a set of filters."; } }
        
        public string ApplicationRecordDataTemplate
            { get { return  """
                            {
                              "type": "qemu",
                              "tags": {
                                "allowed": [
                                  "autodiscovery"
                                ],
                                "excluded": [
                                  "hidden"
                                ]
                              },
                              "networks": {
                                "allowed": [
                                  "10.0.0.0/8",
                                  "172.16.0.0/12",
                                  "192.168.0.0/16",
                                  "fc00::/7"
                                ],
                                "excluded": [
                                  "172.17.0.0/16"
                                ]
                              }
                            }
                            """; } }

        #endregion
        
        private sealed class AppConfig
        {
            [JsonPropertyName("enabled")]
            public bool Enabled { get; set; }
    
            [Required]
            [JsonPropertyName("proxmoxHost")]
            public Uri ProxmoxHost { get; set; }
    
            [JsonPropertyName("timeoutSeconds")]
            public int TimeoutSeconds { get; set; } = 15;
            
            [JsonPropertyName("disableSslValidation")]
            public bool DisableSslValidation { get; set; }
            
            [Required]
            [JsonPropertyName("accessToken")]
            public string AccessToken { get; set; }
    
            [JsonPropertyName("updateIntervalSeconds")]
            public int UpdateIntervalSeconds { get; set; } = 60;
        }
        
        private sealed class AppRecordConfig
        {
            [AllowedValues("lxc", "qemu", null)]
            [JsonPropertyName("type")]
            public string Type { get; set; }
            
            [Required]
            [JsonPropertyName("tags")]
            public Filter<string> Tags { get; set; }
            
            [Required]
            [JsonPropertyName("networks")]
            public Filter<IPNetwork> Networks { get; set; }
        }

        private sealed class Filter<T>
        {
            [Required]
            [JsonPropertyName("allowed")]
            public T[] Allowed { get; set; }
            
            [Required]
            [JsonPropertyName("excluded")]
            public T[] Excluded { get; set; }
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
    }
}
