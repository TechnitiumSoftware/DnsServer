/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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

using DnsServerCore.HttpApi;
using DnsServerCore.HttpApi.Models;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace DnsServerCore.Cluster
{
    //the calls DHCP failover makes to its partner; implemented by a cluster node or by a direct connection
    interface IDhcpFailoverPartner
    {
        Task<DhcpFailoverStatus> GetDhcpFailoverStatusAsync(string selfNodeName, CancellationToken cancellationToken = default);

        Task<Stream> GetDhcpFailoverSnapshotAsync(CancellationToken cancellationToken = default);

        Task SendDhcpFailoverLeaseUpdatesAsync(byte[] leaseUpdates, CancellationToken cancellationToken = default);
    }

    //partner reached directly by URL and API token, without a Cluster
    sealed class DirectDhcpFailoverPartner : IDhcpFailoverPartner, IDisposable
    {
        #region variables

        readonly HttpApiClient _apiClient;

        #endregion

        #region constructor

        public DirectDhcpFailoverPartner(DnsWebService dnsWebService, Uri url, string apiToken, bool ignoreCertificateErrors)
        {
            _apiClient = new HttpApiClient(url, dnsWebService.DnsServer.Proxy, dnsWebService.DnsServer.IPv6Mode, ignoreCertificateErrors);
            _apiClient.UseApiToken(apiToken);
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            _apiClient.Dispose();
        }

        #endregion

        #region public

        public Task<DhcpFailoverStatus> GetDhcpFailoverStatusAsync(string selfNodeName, CancellationToken cancellationToken = default)
        {
            return _apiClient.GetDhcpFailoverStatusAsync(selfNodeName, cancellationToken);
        }

        public Task<Stream> GetDhcpFailoverSnapshotAsync(CancellationToken cancellationToken = default)
        {
            return _apiClient.GetDhcpFailoverSnapshotAsync(cancellationToken);
        }

        public Task SendDhcpFailoverLeaseUpdatesAsync(byte[] leaseUpdates, CancellationToken cancellationToken = default)
        {
            return _apiClient.SendDhcpFailoverLeaseUpdatesAsync(leaseUpdates, cancellationToken);
        }

        #endregion
    }
}
