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
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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

        //SHA-256 of a certificate accepted in addition to normally trusted ones (e.g. the partner's self-signed certificate)
        string _pinnedCertificateFingerprint;
        readonly bool _pinOnFirstUse;
        readonly Action<string> _certificatePinned;

        string _lastUntrustedCertificateFingerprint;

        #endregion

        #region constructor

        public DirectDhcpFailoverPartner(DnsWebService dnsWebService, Uri url, string apiToken, string pinnedCertificateFingerprint, bool pinOnFirstUse, Action<string> certificatePinned)
        {
            _pinnedCertificateFingerprint = pinnedCertificateFingerprint;
            _pinOnFirstUse = pinOnFirstUse;
            _certificatePinned = certificatePinned;

            _apiClient = new HttpApiClient(url, dnsWebService.DnsServer.Proxy, dnsWebService.DnsServer.IPv6Mode, certificateValidationCallback: ValidateCertificate);
            _apiClient.UseApiToken(apiToken);
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            _apiClient.Dispose();
        }

        #endregion

        #region private

        private bool ValidateCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true; //trusted certificate, e.g. one issued by ACME

            if (certificate is null)
                return false;

            string fingerprint = GetCertificateFingerprint(certificate);
            string pinned = _pinnedCertificateFingerprint;

            if (pinned is not null)
            {
                if (fingerprint.Equals(pinned, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            else if (_pinOnFirstUse)
            {
                //only when upgrading a config that ignored certificate errors: remember the certificate in use now
                _pinnedCertificateFingerprint = fingerprint;
                _certificatePinned?.Invoke(fingerprint);
                return true;
            }

            _lastUntrustedCertificateFingerprint = fingerprint;
            return false;
        }

        #endregion

        #region static

        public static string GetCertificateFingerprint(X509Certificate certificate)
        {
            return Convert.ToHexString(SHA256.HashData(certificate.GetRawCertData()));
        }

        public static string NormalizeFingerprint(string fingerprint)
        {
            if (string.IsNullOrWhiteSpace(fingerprint))
                return null;

            string value = fingerprint.Replace(":", "").Replace(" ", "").Replace("-", "").Trim().ToUpperInvariant();

            if ((value.Length != 64) || !IsHex(value))
                throw new DnsWebServiceException("The partner certificate fingerprint must be a SHA-256 hash: 64 hex characters, colons optional.");

            return value;
        }

        private static bool IsHex(string value)
        {
            foreach (char c in value)
            {
                if (!char.IsAsciiHexDigit(c))
                    return false;
            }

            return true;
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

        #region properties

        public string LastUntrustedCertificateFingerprint
        { get { return _lastUntrustedCertificateFingerprint; } }

        #endregion
    }
}
