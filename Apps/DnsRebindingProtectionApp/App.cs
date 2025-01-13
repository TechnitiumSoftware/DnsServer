/*
Technitium DNS Server
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

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

using DnsServerCore.ApplicationCommon;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsRebindingProtection
{
    public sealed class App : IDnsApplication, IDnsPostProcessor
    {
        #region variables

        private bool _enableProtection;
        private NetworkAddress[] _bypassNetworks;
        private HashSet<NetworkAddress> _privateNetworks;
        private HashSet<string> _privateDomains;
        private static readonly SemaphoreSlim ConfigWriteLock = new SemaphoreSlim(1, 1);

        #endregion

        #region IDisposable

        public void Dispose()
        {
            // Nothing to dispose of.
        }

        #endregion

        #region private

        private static string GetParentZone(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
                return null;

            int i = domain.IndexOf('.');
            if (i > -1 && i + 1 < domain.Length)
                return domain[(i + 1)..];

            return null;
        }

        private bool IsPrivateDomain(string domain)
        {
            domain = domain.ToLowerInvariant();
            int maxDepth = 10;

            while (domain is not null && maxDepth-- > 0)
            {
                if (_privateDomains.Contains(domain))
                    return true;

                domain = GetParentZone(domain);
            }

            return false;
        }

        private bool IsRebindingAttempt(DnsResourceRecord record)
        {
            if (record.RDATA is null)
                return false;

            IPAddress address;

            switch (record.Type)
            {
                case DnsResourceRecordType.A:
                    if (IsPrivateDomain(record.Name))
                        return false;

                    address = (record.RDATA as DnsARecordData)?.Address;
                    break;

                case DnsResourceRecordType.AAAA:
                    if (IsPrivateDomain(record.Name))
                        return false;

                    address = (record.RDATA as DnsAAAARecordData)?.Address;
                    break;

                default:
                    return false;
            }

            if (address is null)
                return false;

            foreach (NetworkAddress networkAddress in _privateNetworks)
            {
                if (networkAddress.Contains(address))
                    return true;
            }

            return false;
        }

        private bool TryDetectRebinding(IReadOnlyList<DnsResourceRecord> answer, out List<DnsResourceRecord> protectedAnswer)
        {
            protectedAnswer = new List<DnsResourceRecord>();

            for (int i = 0; i < answer.Count; i++)
            {
                DnsResourceRecord record = answer[i];
                if (IsRebindingAttempt(record))
                {
                    protectedAnswer = new List<DnsResourceRecord>(answer.Count);

                    for (int j = 0; j < i; j++)
                        protectedAnswer.Add(answer[j]);

                    for (int j = i + 1; j < answer.Count; j++)
                    {
                        record = answer[j];
                        if (!IsRebindingAttempt(record))
                            protectedAnswer.Add(record);
                    }

                    return true;
                }
            }

            return false;
        }

        #endregion

        #region public

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            if (string.IsNullOrWhiteSpace(config))
                throw new ArgumentNullException(nameof(config), "Configuration cannot be null or empty.");

            await ConfigWriteLock.WaitAsync();
            try
            {
                using JsonDocument jsonDocument = JsonDocument.Parse(config);
                JsonElement jsonConfig = jsonDocument.RootElement;

                _enableProtection = jsonConfig.GetPropertyValue("enableProtection", true);
                _privateNetworks = new HashSet<NetworkAddress>(jsonConfig.ReadArray("privateNetworks", NetworkAddress.Parse));
                _privateDomains = new HashSet<string>(jsonConfig.ReadArray("privateDomains"));

                if (jsonConfig.TryReadArray("bypassNetworks", NetworkAddress.Parse, out NetworkAddress[] bypassNetworks))
                {
                    _bypassNetworks = bypassNetworks;
                }
                else
                {
                    _bypassNetworks = Array.Empty<NetworkAddress>();
                    config = config.Replace("\"privateNetworks\"", "\"bypassNetworks\": [\r\n  ],\r\n  \"privateNetworks\"");
                    await File.WriteAllTextAsync(Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config"), config);
                }
            }
            catch (JsonException ex)
            {
                throw new InvalidOperationException("Failed to parse the DNS server configuration.", ex);
            }
            finally
            {
                ConfigWriteLock.Release();
            }
        }

        public Task<DnsDatagram> PostProcessAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            if (!_enableProtection || response.AuthoritativeAnswer)
                return Task.FromResult(response);

            IPAddress remoteIP = remoteEP.Address;

            foreach (NetworkAddress network in _bypassNetworks)
            {
                if (network.Contains(remoteIP))
                    return Task.FromResult(response);
            }

            if (TryDetectRebinding(response.Answer, out List<DnsResourceRecord> protectedAnswer))
                return Task.FromResult(response.Clone(protectedAnswer));

            return Task.FromResult(response);
        }

        #endregion

        #region properties

        public string Description
        { get { return "Protects from DNS rebinding attacks using configured private domains and networks."; } }

        #endregion
    }
}
