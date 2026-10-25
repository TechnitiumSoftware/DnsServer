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

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Http.Client;

namespace DnsServerCore.Acme
{
    enum AcmeKeyType : byte
    {
        EcdsaP256 = 1,
        Rsa2048 = 2
    }

    //Obtains and renews this server's own TLS certificate (web service and DNS-over-TLS/HTTPS/QUIC)
    //using ACME with dns-01 challenges.
    sealed class AcmeManager : IDisposable
    {
        #region variables

        public const string LETS_ENCRYPT_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory";
        public const string LETS_ENCRYPT_STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory";

        const int RENEWAL_CHECK_INITIAL_DELAY = 2 * 60 * 1000;
        const int RENEWAL_CHECK_INTERVAL = 6 * 60 * 60 * 1000;
        const int MAX_LOG_ENTRIES = 200;

        readonly DnsWebService _dnsWebService;
        readonly string _acmeFolder;

        //settings
        bool _enabled;
        string _directoryUrl = LETS_ENCRYPT_STAGING_DIRECTORY; //staging by default so first attempts don't hit production rate limits
        string _email;
        bool _termsOfServiceAgreed;
        string _eabKeyId;
        string _eabHmacKey;
        IReadOnlyList<string> _domains = [];
        AcmeKeyType _keyType = AcmeKeyType.EcdsaP256;
        ushort _renewDaysBeforeExpiry = 30;
        bool _useForWebService = true;
        bool _useForDnsTls = true;
        Dns01ProviderType _providerType = Dns01ProviderType.LocalZone;
        string _rfc2136Server;
        string _rfc2136TsigKeyName;
        string _cloudflareApiToken;
        ushort _propagationTimeoutSeconds = 300;
        IReadOnlyList<IPAddress> _publicResolvers = [IPAddress.Parse("1.1.1.1"), IPAddress.Parse("8.8.8.8"), IPAddress.Parse("9.9.9.9")];

        //account and certificate state
        byte[] _accountKeyPkcs8;
        string _accountUrl;
        string _accountDirectoryUrl;
        string _certificatePassword;

        //runtime status
        readonly SemaphoreSlim _runLock = new SemaphoreSlim(1, 1);
        readonly Lock _configLock = new Lock();
        readonly CancellationTokenSource _shutdownCts = new CancellationTokenSource();
        readonly Timer _renewalTimer;
        volatile bool _running;
        DateTime _lastAttempt;
        DateTime _lastSuccess;
        string _lastError;
        readonly List<string> _log = new List<string>();

        #endregion

        #region constructor

        public AcmeManager(DnsWebService dnsWebService)
        {
            _dnsWebService = dnsWebService;
            _acmeFolder = Path.Combine(dnsWebService.ConfigFolder, "acme");

            LoadConfigFile();

            _renewalTimer = new Timer(RenewalTimerCallbackAsync, null, RENEWAL_CHECK_INITIAL_DELAY, RENEWAL_CHECK_INTERVAL);
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            _renewalTimer.Dispose();

            //stop a running issuance so it doesn't install certificates during shutdown
            _shutdownCts.Cancel();

            _disposed = true;
        }

        #endregion

        #region config

        private string ConfigFile
        { get { return Path.Combine(_acmeFolder, "acme.config"); } }

        public string CertificateFile
        { get { return Path.Combine(_acmeFolder, "certificate.pfx"); } }

        private static void WriteString(BinaryWriter bW, string value)
        {
            bW.Write(value ?? "");
        }

        private static string ReadString(BinaryReader bR)
        {
            string value = bR.ReadString();
            return value.Length == 0 ? null : value;
        }

        private void LoadConfigFile()
        {
            try
            {
                if (!File.Exists(ConfigFile))
                    return;

                using (FileStream fS = new FileStream(ConfigFile, FileMode.Open, FileAccess.Read))
                {
                    BinaryReader bR = new BinaryReader(fS);

                    if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "AC")
                        throw new InvalidDataException("ACME config file format is invalid.");

                    byte version = bR.ReadByte();
                    if (version != 1)
                        throw new InvalidDataException("ACME config file version not supported.");

                    _enabled = bR.ReadBoolean();
                    _directoryUrl = ReadString(bR) ?? LETS_ENCRYPT_STAGING_DIRECTORY;
                    _email = ReadString(bR);
                    _termsOfServiceAgreed = bR.ReadBoolean();
                    _eabKeyId = ReadString(bR);
                    _eabHmacKey = ReadString(bR);

                    string[] domains = new string[bR.ReadByte()];
                    for (int i = 0; i < domains.Length; i++)
                        domains[i] = bR.ReadString();

                    _domains = domains;

                    _keyType = (AcmeKeyType)bR.ReadByte();
                    _renewDaysBeforeExpiry = bR.ReadUInt16();
                    _useForWebService = bR.ReadBoolean();
                    _useForDnsTls = bR.ReadBoolean();

                    _providerType = (Dns01ProviderType)bR.ReadByte();
                    _rfc2136Server = ReadString(bR);
                    _rfc2136TsigKeyName = ReadString(bR);
                    _cloudflareApiToken = ReadString(bR);
                    _propagationTimeoutSeconds = bR.ReadUInt16();

                    IPAddress[] resolvers = new IPAddress[bR.ReadByte()];
                    for (int i = 0; i < resolvers.Length; i++)
                        resolvers[i] = IPAddressExtensions.ReadFrom(bR);

                    if (resolvers.Length > 0)
                        _publicResolvers = resolvers;

                    int keyLength = bR.ReadInt32();
                    _accountKeyPkcs8 = keyLength > 0 ? bR.ReadBytes(keyLength) : null;
                    _accountUrl = ReadString(bR);
                    _accountDirectoryUrl = ReadString(bR);
                    _certificatePassword = ReadString(bR);
                }
            }
            catch (Exception ex)
            {
                _enabled = false;
                _dnsWebService.LogManager.Write("ACME: failed to load config file: " + ConfigFile, ex);
            }
        }

        private void SaveConfigFile()
        {
            lock (_configLock)
            {
                SaveConfigFileInternal();
            }
        }

        private void SaveConfigFileInternal()
        {
            Directory.CreateDirectory(_acmeFolder);

            string tmpFile = ConfigFile + ".tmp";

            using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.Write))
            {
                BinaryWriter bW = new BinaryWriter(fS);

                bW.Write(Encoding.ASCII.GetBytes("AC"));
                bW.Write((byte)1); //version

                bW.Write(_enabled);
                WriteString(bW, _directoryUrl);
                WriteString(bW, _email);
                bW.Write(_termsOfServiceAgreed);
                WriteString(bW, _eabKeyId);
                WriteString(bW, _eabHmacKey);

                bW.Write(Convert.ToByte(_domains.Count));
                foreach (string domain in _domains)
                    bW.Write(domain);

                bW.Write((byte)_keyType);
                bW.Write(_renewDaysBeforeExpiry);
                bW.Write(_useForWebService);
                bW.Write(_useForDnsTls);

                bW.Write((byte)_providerType);
                WriteString(bW, _rfc2136Server);
                WriteString(bW, _rfc2136TsigKeyName);
                WriteString(bW, _cloudflareApiToken);
                bW.Write(_propagationTimeoutSeconds);

                bW.Write(Convert.ToByte(_publicResolvers.Count));
                foreach (IPAddress resolver in _publicResolvers)
                    resolver.WriteTo(bW);

                if (_accountKeyPkcs8 is null)
                {
                    bW.Write(0);
                }
                else
                {
                    bW.Write(_accountKeyPkcs8.Length);
                    bW.Write(_accountKeyPkcs8);
                }

                WriteString(bW, _accountUrl);
                WriteString(bW, _accountDirectoryUrl);
                WriteString(bW, _certificatePassword);
            }

            File.Move(tmpFile, ConfigFile, true);
        }

        #endregion

        #region private

        private void Log(string message)
        {
            lock (_log)
            {
                _log.Add(DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss") + " UTC  " + message);

                if (_log.Count > MAX_LOG_ENTRIES)
                    _log.RemoveRange(0, _log.Count - MAX_LOG_ENTRIES);
            }

            _dnsWebService.LogManager.Write("ACME: " + message);
        }

        private HttpClientNetworkHandler CreateHttpHandler()
        {
            HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
            handler.Proxy = _dnsWebService.DnsServer.Proxy;
            handler.NetworkType = HttpClientNetworkHandler.GetNetworkType(_dnsWebService.DnsServer.IPv6Mode);
            handler.DnsClient = _dnsWebService.DnsServer;

            return handler;
        }

        private IDns01Provider CreateProvider(HttpClientNetworkHandler handler)
        {
            switch (_providerType)
            {
                case Dns01ProviderType.LocalZone:
                    return new LocalZoneDns01Provider(_dnsWebService.DnsServer);

                case Dns01ProviderType.Rfc2136:
                    TsigKey tsigKey = null;

                    if (!string.IsNullOrEmpty(_rfc2136TsigKeyName))
                    {
                        if ((_dnsWebService.DnsServer.TsigKeys is null) || !_dnsWebService.DnsServer.TsigKeys.TryGetValue(_rfc2136TsigKeyName, out tsigKey))
                            throw new AcmeException("TSIG key '" + _rfc2136TsigKeyName + "' is not defined in Settings > TSIG.");
                    }

                    return new Rfc2136Dns01Provider(_rfc2136Server, tsigKey);

                case Dns01ProviderType.Cloudflare:
                    return new CloudflareDns01Provider(handler, _cloudflareApiToken);

                default:
                    throw new AcmeException("Unknown DNS-01 provider.");
            }
        }

        private ECDsa GetOrCreateAccountKey()
        {
            ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            if ((_accountKeyPkcs8 is not null) && (_accountDirectoryUrl == _directoryUrl))
            {
                key.ImportPkcs8PrivateKey(_accountKeyPkcs8, out _);
            }
            else
            {
                //new CA (or first run): new account key and account
                _accountKeyPkcs8 = key.ExportPkcs8PrivateKey();
                _accountUrl = null;
                _accountDirectoryUrl = _directoryUrl;
            }

            return key;
        }

        private void ValidateForIssuance()
        {
            if (!_termsOfServiceAgreed)
                throw new AcmeException("The certificate authority's terms of service have not been agreed to.");

            if (_domains.Count == 0)
                throw new AcmeException("No domain names are configured.");

            if (!_useForWebService && !_useForDnsTls)
                throw new AcmeException("The certificate is not set to be used for the web service or DNS-over-TLS/HTTPS/QUIC.");
        }

        private X509Certificate2 LoadCurrentCertificate()
        {
            try
            {
                if (!File.Exists(CertificateFile) || (_certificatePassword is null))
                    return null;

                foreach (X509Certificate2 certificate in X509CertificateLoader.LoadPkcs12CollectionFromFile(CertificateFile, _certificatePassword))
                {
                    if (certificate.HasPrivateKey)
                        return certificate;
                }
            }
            catch (Exception ex)
            {
                _dnsWebService.LogManager.Write("ACME: failed to read current certificate: " + CertificateFile, ex);
            }

            return null;
        }

        private static IReadOnlyList<string> GetCertificateDnsNames(X509Certificate2 certificate)
        {
            List<string> names = new List<string>();

            foreach (X509Extension extension in certificate.Extensions)
            {
                if (extension is X509SubjectAlternativeNameExtension san)
                    names.AddRange(san.EnumerateDnsNames());
            }

            return names;
        }

        private string GetRenewalReason()
        {
            X509Certificate2 current = LoadCurrentCertificate();

            if (current is null)
                return "no certificate has been issued yet";

            IReadOnlyList<string> names = GetCertificateDnsNames(current);

            if ((names.Count != _domains.Count) || _domains.Any(d => !names.Contains(d, StringComparer.OrdinalIgnoreCase)))
                return "the configured domain names changed";

            if (current.NotAfter.ToUniversalTime() < DateTime.UtcNow.AddDays(_renewDaysBeforeExpiry))
                return "the certificate expires on " + current.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd") + " (renewing " + _renewDaysBeforeExpiry + " days before expiry)";

            return null;
        }

        private async void RenewalTimerCallbackAsync(object state)
        {
            try
            {
                if (!_enabled || _running)
                    return;

                string reason = GetRenewalReason();
                if (reason is null)
                    return;

                Log("Automatic renewal: " + reason + ".");
                await RunAsync();
            }
            catch (Exception ex)
            {
                _dnsWebService.LogManager.Write(ex);
            }
        }

        private async Task RegisterAccountAsync(AcmeClient client, CancellationToken cancellationToken)
        {
            (string termsUrl, bool eabRequired) = await client.GetDirectoryMetaAsync(cancellationToken);

            if (eabRequired && (string.IsNullOrEmpty(_eabKeyId) || string.IsNullOrEmpty(_eabHmacKey)))
                throw new AcmeException("This certificate authority requires External Account Binding (EAB) credentials.");

            Log("Registering ACME account at " + _directoryUrl + (termsUrl is null ? "" : " (terms of service: " + termsUrl + ")") + ".");
            _accountUrl = await client.CreateOrFindAccountAsync(_email, _termsOfServiceAgreed, _eabKeyId, _eabHmacKey, cancellationToken);
            SaveConfigFile();
        }

        private async Task IssueAsync(CancellationToken cancellationToken)
        {
            ValidateForIssuance();

            //one consistent set of names for the order and the CSR even if settings are saved meanwhile
            IReadOnlyList<string> domains = _domains;

            using HttpClientNetworkHandler handler = CreateHttpHandler();
            IDns01Provider provider = CreateProvider(handler);
            Dns01Resolver resolver = new Dns01Resolver(_publicResolvers);
            TimeSpan propagationTimeout = TimeSpan.FromSeconds(_propagationTimeoutSeconds);

            using ECDsa accountKey = GetOrCreateAccountKey();
            using AcmeClient client = new AcmeClient(handler, new Uri(_directoryUrl), accountKey, _accountUrl);

            //account
            if (_accountUrl is null)
                await RegisterAccountAsync(client, cancellationToken);

            //order
            Log("Ordering certificate for " + string.Join(", ", domains) + ".");
            AcmeOrder order;

            try
            {
                order = await client.NewOrderAsync(domains, cancellationToken);
            }
            catch (AcmeException ex) when ((ex.ProblemType == "urn:ietf:params:acme:error:accountDoesNotExist") || (ex.ProblemType == "urn:ietf:params:acme:error:unauthorized"))
            {
                //account was deactivated or the CA was reset; register again with the same key and retry once
                Log("ACME account is no longer valid (" + ex.ProblemType + "); registering again.");
                await RegisterAccountAsync(client, cancellationToken);
                order = await client.NewOrderAsync(domains, cancellationToken);
            }

            List<(string recordName, string value)> published = new List<(string, string)>();

            try
            {
                List<AcmeAuthorization> pending = new List<AcmeAuthorization>();

                foreach (string authorizationUrl in order.AuthorizationUrls)
                {
                    AcmeAuthorization authorization = await client.GetAuthorizationAsync(authorizationUrl, cancellationToken);

                    if (authorization.Status == "valid")
                        continue; //recently validated; CA reuses it

                    if (authorization.Dns01Challenge is null)
                        throw new AcmeException("The certificate authority did not offer a dns-01 challenge for " + authorization.Identifier + ".");

                    string recordName = await resolver.ResolveChallengeNameAsync("_acme-challenge." + authorization.Identifier, cancellationToken);
                    string value = client.GetDns01TxtValue(authorization.Dns01Challenge.Token);

                    Log("Publishing TXT record " + recordName + (recordName.StartsWith("_acme-challenge." + authorization.Identifier, StringComparison.OrdinalIgnoreCase) ? "" : " (CNAME delegated)") + " via " + _providerType + ".");
                    await provider.AddTxtRecordAsync(recordName, value, cancellationToken);
                    published.Add((recordName, value));

                    pending.Add(authorization);
                }

                foreach ((string recordName, string value) in published)
                    await resolver.WaitForPropagationAsync(recordName, value, propagationTimeout, Log, cancellationToken);

                foreach (AcmeAuthorization authorization in pending)
                {
                    await client.RespondToChallengeAsync(authorization.Dns01Challenge.Url, cancellationToken);
                    await client.WaitForAuthorizationAsync(authorization.Url, TimeSpan.FromMinutes(3), cancellationToken);
                    Log("Validated " + (authorization.Wildcard ? "*." : "") + authorization.Identifier + ".");
                }
            }
            finally
            {
                foreach ((string recordName, string value) in published)
                {
                    try
                    {
                        await provider.RemoveTxtRecordAsync(recordName, value, CancellationToken.None);
                    }
                    catch (Exception ex)
                    {
                        Log("Failed to remove TXT record " + recordName + ": " + ex.Message);
                    }
                }
            }

            //certificate key and CSR
            AsymmetricAlgorithm certificateKey;
            CertificateRequest csr;
            string subject = "CN=" + domains[0];

            if (_keyType == AcmeKeyType.Rsa2048)
            {
                RSA rsa = RSA.Create(2048);
                certificateKey = rsa;
                csr = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            else
            {
                ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                certificateKey = ecdsa;
                csr = new CertificateRequest(subject, ecdsa, HashAlgorithmName.SHA256);
            }

            using (certificateKey)
            {
                SubjectAlternativeNameBuilder san = new SubjectAlternativeNameBuilder();
                foreach (string domain in domains)
                    san.AddDnsName(domain);

                csr.CertificateExtensions.Add(san.Build());

                order = await client.FinalizeAsync(order, csr.CreateSigningRequest(), TimeSpan.FromMinutes(3), cancellationToken);
                string chainPem = await client.DownloadCertificateChainPemAsync(order, cancellationToken);

                //PKCS #12 with the private key on the leaf and the issuer chain, which the web service and DNS server load as-is
                X509Certificate2Collection chain = new X509Certificate2Collection();
                chain.ImportFromPem(chainPem);

                X509Certificate2 leaf = chain[0];
                X509Certificate2 leafWithKey = certificateKey is RSA rsaKey ? leaf.CopyWithPrivateKey(rsaKey) : leaf.CopyWithPrivateKey((ECDsa)certificateKey);

                X509Certificate2Collection pfx = new X509Certificate2Collection(leafWithKey);
                for (int i = 1; i < chain.Count; i++)
                    pfx.Add(chain[i]);

                //persist the password before the file it protects, so a failure can't leave an unreadable PFX
                if (_certificatePassword is null)
                {
                    _certificatePassword = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
                    SaveConfigFile();
                }

                Directory.CreateDirectory(_acmeFolder);
                string tmpFile = CertificateFile + ".tmp";
                File.WriteAllBytes(tmpFile, pfx.Export(X509ContentType.Pkcs12, _certificatePassword));
                File.Move(tmpFile, CertificateFile, true);

                Log("Certificate issued by " + leaf.Issuer + ", valid until " + leaf.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd HH:mm") + " UTC.");
            }

            InstallCertificate();
        }

        private void InstallCertificate()
        {
            if (_useForWebService)
            {
                _dnsWebService.InstallWebServiceTlsCertificate(CertificateFile, _certificatePassword);
                Log("Installed certificate for the web service (HTTPS).");
            }

            if (_useForDnsTls)
            {
                _dnsWebService.InstallDnsTlsCertificate(CertificateFile, _certificatePassword);
                Log("Installed certificate for DNS-over-TLS/HTTPS/QUIC.");
            }
        }

        #endregion

        #region public

        //Issues or renews the certificate now. Returns false if a run is already in progress.
        public async Task<bool> RunAsync()
        {
            if (!await _runLock.WaitAsync(0))
                return false;

            _running = true;
            _lastAttempt = DateTime.UtcNow;

            try
            {
                using (CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(_shutdownCts.Token))
                {
                    cts.CancelAfter(TimeSpan.FromMinutes(20));
                    await IssueAsync(cts.Token);
                }

                _lastSuccess = DateTime.UtcNow;
                _lastError = null;
            }
            catch (OperationCanceledException) when (_shutdownCts.IsCancellationRequested)
            {
                _lastError = "Stopped because the DNS server is shutting down.";
            }
            catch (OperationCanceledException)
            {
                _lastError = "Timed out after 20 minutes.";
                Log("Failed: " + _lastError);
            }
            catch (Exception ex)
            {
                _lastError = ex is AcmeException ? ex.Message : ex.ToString();
                Log("Failed: " + _lastError);
            }
            finally
            {
                _running = false;
                _runLock.Release();
            }

            return true;
        }

        //Publishes a test TXT record with the configured provider, waits for it to be visible on the public
        //authoritative servers, then removes it. Does not contact the certificate authority.
        public async Task<string> TestDns01Async(CancellationToken cancellationToken)
        {
            if (_domains.Count == 0)
                throw new AcmeException("No domain names are configured.");

            using HttpClientNetworkHandler handler = CreateHttpHandler();
            IDns01Provider provider = CreateProvider(handler);
            Dns01Resolver resolver = new Dns01Resolver(_publicResolvers);

            string domain = _domains[0].StartsWith("*.") ? _domains[0].Substring(2) : _domains[0];
            string recordName = await resolver.ResolveChallengeNameAsync("_acme-challenge." + domain, cancellationToken);
            string value = "technitium-dns01-test-" + AcmeClient.Base64Url(RandomNumberGenerator.GetBytes(12));

            Log("Test: publishing TXT record " + recordName + " via " + _providerType + ".");
            await provider.AddTxtRecordAsync(recordName, value, cancellationToken);

            try
            {
                await resolver.WaitForPropagationAsync(recordName, value, TimeSpan.FromSeconds(_propagationTimeoutSeconds), Log, cancellationToken);
            }
            finally
            {
                await provider.RemoveTxtRecordAsync(recordName, value, CancellationToken.None);
            }

            string result = "DNS-01 test passed: " + recordName + " was published, seen on the public authoritative name servers, and removed.";
            Log(result);
            return result;
        }

        //null string arguments keep the saved value; empty strings clear it (secrets: empty also keeps, see API)
        public void SetConfig(bool enabled, string directoryUrl, string email, bool termsOfServiceAgreed, string eabKeyId, string eabHmacKey, IReadOnlyList<string> domains, AcmeKeyType keyType, ushort renewDaysBeforeExpiry, bool useForWebService, bool useForDnsTls, Dns01ProviderType providerType, string rfc2136Server, string rfc2136TsigKeyName, string cloudflareApiToken, ushort propagationTimeoutSeconds, IReadOnlyList<IPAddress> publicResolvers)
        {
            if (!Uri.TryCreate(directoryUrl, UriKind.Absolute, out Uri directoryUri) || (directoryUri.Scheme != Uri.UriSchemeHttps))
                throw new AcmeException("The ACME directory URL must be an absolute https:// URL.");

            if (domains.Count > 100)
                throw new AcmeException("At most 100 domain names can be configured.");

            List<string> normalized = new List<string>();

            foreach (string domain in domains)
            {
                string d = domain.Trim().TrimEnd('.').ToLowerInvariant();
                if (d.Length == 0)
                    continue;

                string check = d.StartsWith("*.") ? d.Substring(2) : d;

                if (!DnsClient.IsDomainNameValid(check) || check.Contains('*'))
                    throw new AcmeException("Invalid domain name: " + domain);

                if (!normalized.Contains(d))
                    normalized.Add(d);
            }

            if ((renewDaysBeforeExpiry < 1) || (renewDaysBeforeExpiry > 60))
                throw new AcmeException("Renew before expiry must be between 1 and 60 days.");

            if ((propagationTimeoutSeconds < 30) || (propagationTimeoutSeconds > 3600))
                throw new AcmeException("Propagation timeout must be between 30 and 3600 seconds.");

            if (publicResolvers.Count is 0 or > 10)
                throw new AcmeException("Between 1 and 10 public resolvers must be configured.");

            if (enabled)
            {
                if (!termsOfServiceAgreed)
                    throw new AcmeException("You must agree to the certificate authority's terms of service to enable ACME.");

                if (normalized.Count == 0)
                    throw new AcmeException("At least one domain name is required.");

                if (!useForWebService && !useForDnsTls)
                    throw new AcmeException("Select where the certificate is used: the web service, DNS-over-TLS/HTTPS/QUIC, or both.");

                if ((providerType == Dns01ProviderType.Rfc2136) && string.IsNullOrWhiteSpace(rfc2136Server ?? _rfc2136Server))
                    throw new AcmeException("The RFC 2136 provider requires the dynamic update server address.");

                if ((providerType == Dns01ProviderType.Cloudflare) && string.IsNullOrWhiteSpace(cloudflareApiToken ?? _cloudflareApiToken))
                    throw new AcmeException("The Cloudflare provider requires an API token.");
            }

            //don't change settings under a running issuance (order and CSR must use the same names)
            if (!_runLock.Wait(0))
                throw new AcmeException("A certificate request is in progress. Save the settings again when it has finished.");

            try
            {
                SetConfigInternal(enabled, directoryUrl, email, termsOfServiceAgreed, eabKeyId, eabHmacKey, normalized, keyType, renewDaysBeforeExpiry, useForWebService, useForDnsTls, providerType, rfc2136Server, rfc2136TsigKeyName, cloudflareApiToken, propagationTimeoutSeconds, publicResolvers);
            }
            finally
            {
                _runLock.Release();
            }
        }

        //null string arguments keep the saved value; empty strings clear it
        private void SetConfigInternal(bool enabled, string directoryUrl, string email, bool termsOfServiceAgreed, string eabKeyId, string eabHmacKey, IReadOnlyList<string> normalized, AcmeKeyType keyType, ushort renewDaysBeforeExpiry, bool useForWebService, bool useForDnsTls, Dns01ProviderType providerType, string rfc2136Server, string rfc2136TsigKeyName, string cloudflareApiToken, ushort propagationTimeoutSeconds, IReadOnlyList<IPAddress> publicResolvers)
        {
            //a different CA needs a new account, and its terms must be agreed to separately
            if (directoryUrl != _directoryUrl)
            {
                _accountUrl = null;
                _accountDirectoryUrl = null;
                _accountKeyPkcs8 = null;
            }

            _enabled = enabled;
            _directoryUrl = directoryUrl;

            if (email is not null)
                _email = string.IsNullOrWhiteSpace(email) ? null : email.Trim();

            _termsOfServiceAgreed = termsOfServiceAgreed;

            if (eabKeyId is not null)
                _eabKeyId = string.IsNullOrWhiteSpace(eabKeyId) ? null : eabKeyId.Trim();

            if (eabHmacKey is not null) //null keeps the saved secret
                _eabHmacKey = eabHmacKey.Length == 0 ? null : eabHmacKey.Trim();

            _domains = normalized;
            _keyType = keyType;
            _renewDaysBeforeExpiry = renewDaysBeforeExpiry;
            _useForWebService = useForWebService;
            _useForDnsTls = useForDnsTls;
            _providerType = providerType;

            if (rfc2136Server is not null)
                _rfc2136Server = string.IsNullOrWhiteSpace(rfc2136Server) ? null : rfc2136Server.Trim();

            if (rfc2136TsigKeyName is not null)
                _rfc2136TsigKeyName = string.IsNullOrWhiteSpace(rfc2136TsigKeyName) ? null : rfc2136TsigKeyName.Trim();

            if (cloudflareApiToken is not null) //null keeps the saved secret
                _cloudflareApiToken = cloudflareApiToken.Length == 0 ? null : cloudflareApiToken.Trim();

            _propagationTimeoutSeconds = propagationTimeoutSeconds;
            _publicResolvers = publicResolvers;

            SaveConfigFile();
        }

        public X509Certificate2 GetCurrentCertificate()
        {
            return LoadCurrentCertificate();
        }

        public string[] GetLog()
        {
            lock (_log)
                return _log.ToArray();
        }

        #endregion

        #region properties

        public bool Enabled { get { return _enabled; } }
        public string DirectoryUrl { get { return _directoryUrl; } }
        public string Email { get { return _email; } }
        public bool TermsOfServiceAgreed { get { return _termsOfServiceAgreed; } }
        public string EabKeyId { get { return _eabKeyId; } }
        public bool EabHmacKeySet { get { return _eabHmacKey is not null; } }
        public IReadOnlyList<string> Domains { get { return _domains; } }
        public AcmeKeyType KeyType { get { return _keyType; } }
        public ushort RenewDaysBeforeExpiry { get { return _renewDaysBeforeExpiry; } }
        public bool UseForWebService { get { return _useForWebService; } }
        public bool UseForDnsTls { get { return _useForDnsTls; } }
        public Dns01ProviderType ProviderType { get { return _providerType; } }
        public string Rfc2136Server { get { return _rfc2136Server; } }
        public string Rfc2136TsigKeyName { get { return _rfc2136TsigKeyName; } }
        public bool CloudflareApiTokenSet { get { return _cloudflareApiToken is not null; } }
        public ushort PropagationTimeoutSeconds { get { return _propagationTimeoutSeconds; } }
        public IReadOnlyList<IPAddress> PublicResolvers { get { return _publicResolvers; } }
        public string AccountUrl { get { return _accountUrl; } }
        public bool Running { get { return _running; } }
        public DateTime LastAttempt { get { return _lastAttempt; } }
        public DateTime LastSuccess { get { return _lastSuccess; } }
        public string LastError { get { return _lastError; } }

        #endregion
    }
}
