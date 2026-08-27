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

using DnsServerCore.ApplicationCommon;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Threading;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Security
{
    internal enum CookieRequestState
    {
        NotEvaluated,
        NoCookie,
        ClientOnly,
        InvalidServerCookie,
        ValidServerCookie,
        MalformedCookie
    }

    /// <summary>
    /// The result of classifying one request's COOKIE option, captured once per request against
    /// a single runtime generation. <see cref="DnsCookieCoordinator.Preflight"/> and
    /// <see cref="DnsCookieCoordinator.AttachToResponse"/> both take this same instance so a
    /// secret rotation racing the request cannot make the two calls disagree about which secret
    /// generation is in play.
    /// </summary>
    internal readonly struct CookieRequestClassification
    {
        public DnsCookieCoordinator.RuntimeState RuntimeState { get; }
        public CookieRequestState State { get; }
        public IPAddress CookieClientAddress { get; }
        public EDnsCookieOptionData Cookie { get; }
        public DnsCookieValidationResult ValidationResult { get; }

        public CookieRequestClassification(DnsCookieCoordinator.RuntimeState runtimeState, CookieRequestState state, IPAddress cookieClientAddress,
            EDnsCookieOptionData cookie = null, DnsCookieValidationResult validationResult = DnsCookieValidationResult.Invalid)
        {
            RuntimeState = runtimeState;
            State = state;
            CookieClientAddress = cookieClientAddress;
            Cookie = cookie;
            ValidationResult = validationResult;
        }
    }

    /// <summary>
    /// The outcome of <see cref="DnsCookieCoordinator.Preflight"/>: either a response the caller
    /// must return immediately without further query processing (FORMERR or BADCOOKIE), a
    /// pre-built acquisition acknowledgement the caller should still post-process normally, or
    /// neither, meaning the caller should process the query as usual.
    /// </summary>
    internal readonly struct CookiePreflightResult
    {
        public DnsDatagram Response { get; }
        public bool ShortCircuit { get; }

        private CookiePreflightResult(DnsDatagram response, bool shortCircuit)
        {
            Response = response;
            ShortCircuit = shortCircuit;
        }

        public static readonly CookiePreflightResult None = new CookiePreflightResult(null, false);
        public static CookiePreflightResult Immediate(DnsDatagram response) => new CookiePreflightResult(response, true);
        public static CookiePreflightResult Acquisition(DnsDatagram response) => new CookiePreflightResult(response, false);
    }

    /// <summary>
    /// Owns the DNS Cookie (RFC 7873 / RFC 9018) subsystem end to end: explicit secret
    /// lifecycle, request classification, and the FORMERR/BADCOOKIE/response-cookie
    /// decisions that used to live inline in DnsServer's request pipeline. DnsServer holds one
    /// instance and only ever talks to it through this surface.
    /// </summary>
    public sealed class DnsCookieCoordinator
    {
        private const string SecretFileName = "dns.cookies.state";
        private static readonly TimeSpan DefaultStandaloneAutomaticRotationPeriod = TimeSpan.FromDays(30);

        // Wire-format lengths come from the EDNS COOKIE option type that parsed them, so
        // the server cannot drift away from its own parser.
        private const int ClientCookieLength = EDnsCookieOptionData.CLIENT_COOKIE_LENGTH;
        private const int ServerCookieMinLength = EDnsCookieOptionData.SERVER_COOKIE_MIN_LENGTH;
        private const int ServerCookieMaxLength = EDnsCookieOptionData.SERVER_COOKIE_MAX_LENGTH;
        private const int V1ServerCookieLength = 16;
        private const byte V1Version = 1;

        readonly string _configFolder;
        readonly Lock _lock;
        readonly LogManager _log;

        RuntimeState _state = DisabledState.Instance;
        long _generation;
        bool _enableStandaloneAutomaticRotation;
        TimeSpan _standaloneAutomaticRotationPeriod = DefaultStandaloneAutomaticRotationPeriod;
        Timer _standaloneRotationTimer;

        // Optional observability counters (not currently exposed; see ValidationInvocations for
        // the one counter DnsServer does expose publicly).
        long _validCount;
        long _validCurrentCount;
        long _validRenewCount;
        long _invalidCount;
        long _malformedCount;
        long _missingCount;
        long _badCookieSentCount;
        long _clientOnlyCount;
        long _validationInvocations;

        /// <param name="configFolder">DnsServer's config folder; used only to resolve the default secret file path.</param>
        /// <param name="saveLock">
        /// DnsServer's own config save/reload lock. Secret-state transitions intentionally
        /// serialize against config save/reload with the same lock DnsServer already uses for
        /// that, rather than an independent one, to preserve the original synchronization
        /// between the two.
        /// </param>
        public DnsCookieCoordinator(string configFolder, Lock saveLock, LogManager log)
        {
            _configFolder = configFolder;
            _lock = saveLock;
            _log = log;
        }

        public long ValidationInvocations => Interlocked.Read(ref _validationInvocations);

        #region lifecycle

        public void Configure(bool enabled)
        {
            lock (_lock)
            {
                if (!enabled)
                {
                    Volatile.Write(ref _state, DisabledState.Instance);
                    return;
                }

                try
                {
                    DnsCookieSecretManager secretManager = new DnsCookieSecretManager(GetSecretPath());
                    EnabledState nextState = new EnabledState(NextGeneration(), secretManager);
                    Volatile.Write(ref _state, nextState);
                    if (_enableStandaloneAutomaticRotation)
                        ScheduleStandaloneTransition(secretManager);
                }
                catch (Exception ex) when (ex is InvalidDataException || ex is IOException || ex is UnauthorizedAccessException)
                {
                    Volatile.Write(ref _state, new DegradedState(NextGeneration()));
                    _log.Write(new InvalidOperationException("DNS Cookie protection is degraded because its secret state could not be loaded. The existing state file was not overwritten.", ex));
                }
            }
        }

        /// <summary>Forces the subsystem disabled. Used on server shutdown.</summary>
        public void Stop()
        {
            lock (_lock)
            {
                _standaloneRotationTimer?.Dispose();
                _standaloneRotationTimer = null;
                Volatile.Write(ref _state, DisabledState.Instance);
            }
        }

        public void ConfigureStandaloneAutomaticRotation(bool enabled, TimeSpan rotationPeriod)
        {
            if (rotationPeriod <= TimeSpan.Zero)
                throw new ArgumentOutOfRangeException(nameof(rotationPeriod));

            lock (_lock)
            {
                _enableStandaloneAutomaticRotation = enabled;
                _standaloneAutomaticRotationPeriod = rotationPeriod;
                _standaloneRotationTimer?.Dispose();
                _standaloneRotationTimer = null;

                if (enabled && Volatile.Read(ref _state) is EnabledState current)
                    ScheduleStandaloneTransition(current.SecretManager);
            }
        }

        private long NextGeneration() => Interlocked.Increment(ref _generation);

        private void RotateStandaloneSecrets(DnsCookieSecretManager secretManager)
        {
            lock (_lock)
            {
                if (!_enableStandaloneAutomaticRotation ||
                    Volatile.Read(ref _state) is not EnabledState current ||
                    !ReferenceEquals(current.SecretManager, secretManager))
                {
                    return;
                }

                try
                {
                    if (!secretManager.Rotate())
                    {
                        // Retiring the previous secret requires a TTL-aware operator decision;
                        // see DnsCookieSecretManager.Rotate and RFC 9018 §5.
                        _standaloneRotationTimer?.Dispose();
                        _standaloneRotationTimer = null;
                        return;
                    }

                    Volatile.Write(ref _state, new EnabledState(NextGeneration(), secretManager));
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }

                if (_enableStandaloneAutomaticRotation)
                    ScheduleStandaloneTransition(secretManager);
            }
        }

        private void ScheduleStandaloneTransition(DnsCookieSecretManager secretManager)
        {
            _standaloneRotationTimer?.Dispose();
            _standaloneRotationTimer = null;

            if (secretManager.RolloverState == DnsCookieSecretRolloverState.Activated)
                return; //Retirement is manual so the RFC 9018 TTL-aware hold is never bypassed.

            TimeSpan dueTime = secretManager.GetNextTransitionUtc(_standaloneAutomaticRotationPeriod) - DateTime.UtcNow;
            if (dueTime < TimeSpan.Zero)
                dueTime = TimeSpan.Zero;

            _standaloneRotationTimer = new Timer(_ => RotateStandaloneSecrets(secretManager), null,
                dueTime, Timeout.InfiniteTimeSpan);
        }

        private string GetSecretPath()
        {
            return Path.IsPathRooted(SecretFileName)
                ? SecretFileName
                : Path.Combine(_configFolder, SecretFileName);
        }

        private DnsCookieSecretManager GetOrCreateSecrets()
        {
            RuntimeState state = Volatile.Read(ref _state);
            return state is EnabledState enabled
                ? enabled.SecretManager
                : new DnsCookieSecretManager(GetSecretPath());
        }

        /// <param name="cookiesEnabled">
        /// The caller's current enabled flag, passed in rather than owned here so a secret edit
        /// that races a disable cannot re-publish an EnabledState snapshot after the caller has
        /// already committed to disabling (mirrors the flag's original placement on DnsServer).
        /// </param>
        public void UpdateSecrets(bool cookiesEnabled, Action<DnsCookieSecretManager> update)
        {
            lock (_lock)
            {
                DnsCookieSecretManager secretManager = GetOrCreateSecrets();
                update(secretManager);

                if (cookiesEnabled &&
                    Volatile.Read(ref _state) is EnabledState current &&
                    ReferenceEquals(current.SecretManager, secretManager))
                {
                    Volatile.Write(ref _state, new EnabledState(NextGeneration(), secretManager));
                    if (_enableStandaloneAutomaticRotation)
                        ScheduleStandaloneTransition(secretManager);
                }
            }
        }

        // Status lookup is deliberately non-creating. When cookies are disabled and no
        // persisted state exists, false is returned and all output values are unavailable.
        public bool TryGetStatus(out string activeId, out string stagingId, out DateTime activeCreatedUtc)
        {
            return TryGetCoordinationStatus(out _, out _, out activeId, out stagingId, out activeCreatedUtc);
        }

        public bool TryGetCoordinationStatus(out long generation, out DnsCookieSecretRolloverState rolloverState,
            out string activeId, out string stagingId, out DateTime activeCreatedUtc)
        {
            lock (_lock)
            {
                if (Volatile.Read(ref _state) is EnabledState enabled)
                {
                    generation = enabled.SecretManager.Generation;
                    rolloverState = enabled.SecretManager.RolloverState;
                    enabled.SecretManager.GetStatus(out activeId, out stagingId, out activeCreatedUtc);
                    return true;
                }

                generation = 0;
                rolloverState = DnsCookieSecretRolloverState.None;
                return DnsCookieSecretManager.TryGetStatus(GetSecretPath(), out activeId, out stagingId, out activeCreatedUtc);
            }
        }

        public void Import(Stream stream) => UpdateSecrets(true, secrets => secrets.Import(stream));

        public void Export(Stream stream) => GetOrCreateSecrets().Export(stream);

        /// <summary>
        /// Gets comprehensive DNS Cookie statistics for monitoring and attack detection.
        /// RFC 9018 §9 recommends tracking these to detect when a server is under attack.
        /// </summary>
        public DnsCookieStatistics GetStatistics()
        {
            return new DnsCookieStatistics(
                Interlocked.Read(ref _validationInvocations),
                Interlocked.Read(ref _validCount),
                Interlocked.Read(ref _validCurrentCount),
                Interlocked.Read(ref _validRenewCount),
                Interlocked.Read(ref _invalidCount),
                Interlocked.Read(ref _malformedCount),
                Interlocked.Read(ref _missingCount),
                Interlocked.Read(ref _badCookieSentCount),
                Interlocked.Read(ref _clientOnlyCount));
        }

        #endregion

        #region request classification

        // This is deliberately a statement about return-routability only. A valid cookie
        // bypasses reflection RRL, but does not bypass any other admission, query, or
        // resource-control policy.
        internal CookieRequestClassification Classify(DnsDatagram request, IPAddress clientAddress, DnsTransportProtocol protocol)
        {
            RuntimeState runtimeState = Volatile.Read(ref _state);
            if (!SupportsDnsCookies(protocol) || runtimeState is not EnabledState enabledState)
                return new CookieRequestClassification(runtimeState, CookieRequestState.NotEvaluated, clientAddress);

            return ClassifyEnabled(request, clientAddress, enabledState);
        }

        private CookieRequestClassification ClassifyEnabled(DnsDatagram request, IPAddress clientAddress, EnabledState runtimeState)
        {
            if (request.EDNS is null)
                return new CookieRequestClassification(runtimeState, CookieRequestState.NoCookie, clientAddress);

            // RFC 7873 says to process only the first COOKIE option.  In particular,
            // never let a later valid option repair a malformed or invalid first one.
            foreach (EDnsOption option in request.EDNS.Options)
            {
                if (option.Code != EDnsOptionCode.COOKIE)
                    continue;

                if (option.Data is not EDnsCookieOptionData cookieData)
                    return new CookieRequestClassification(runtimeState, CookieRequestState.MalformedCookie, clientAddress);

                // The option parser already applied these length rules and kept the raw
                // payload for FORMERR; re-deriving the verdict here just invites the two
                // to disagree.
                if (cookieData.IsMalformed)
                    return new CookieRequestClassification(runtimeState, CookieRequestState.MalformedCookie, clientAddress, cookieData);

                int serverLength = cookieData.ServerCookie.Length;

                if (serverLength == 0)
                    return new CookieRequestClassification(runtimeState, CookieRequestState.ClientOnly, clientAddress, cookieData);

                DnsCookieValidator validator = runtimeState.Validator;
                if (serverLength != V1ServerCookieLength || cookieData.ServerCookie[0] != V1Version)
                {
                    return new CookieRequestClassification(runtimeState, CookieRequestState.InvalidServerCookie, clientAddress, cookieData);
                }

                Interlocked.Increment(ref _validationInvocations);
                DnsCookieValidationResult validationResult =
                    validator.Validate(clientAddress, cookieData.ClientCookie, cookieData.ServerCookie);
                return validationResult == DnsCookieValidationResult.Invalid
                    ? new CookieRequestClassification(runtimeState, CookieRequestState.InvalidServerCookie, clientAddress, cookieData)
                    : new CookieRequestClassification(runtimeState, CookieRequestState.ValidServerCookie, clientAddress, cookieData, validationResult);
            }

            return new CookieRequestClassification(runtimeState, CookieRequestState.NoCookie, clientAddress);
        }

        #endregion

        #region request/response decisions

        /// <summary>
        /// Evaluates the classified COOKIE option before the query is processed. A
        /// <see cref="CookiePreflightResult.ShortCircuit"/> result (FORMERR or BADCOOKIE) must be
        /// returned to the client immediately, without post-processing. Otherwise, a non-null
        /// <see cref="CookiePreflightResult.Response"/> is a pre-built RFC 7873 section 5.4
        /// zero-question acquisition acknowledgement that should still flow through normal
        /// post-processing; a null response means the caller should process the query as usual.
        /// </summary>
        internal CookiePreflightResult Preflight(DnsDatagram request, IPAddress cookieClientAddress, DnsTransportProtocol protocol, bool isRecursionAllowed,
            in CookieRequestClassification classification, ushort udpPayloadSizeFallback)
        {
            if (!SupportsDnsCookies(protocol) || request.EDNS is null || classification.RuntimeState is not EnabledState cookieRuntimeState)
                return CookiePreflightResult.None;

            EDnsCookieOptionData requestCookie = classification.Cookie;
            bool isCookieAcquisitionRequest = IsCookieAcquisitionRequest(request, classification.State);

            if (classification.State == CookieRequestState.NoCookie)
            {
                Interlocked.Increment(ref _missingCount);
            }
            else
            {
                if (classification.State == CookieRequestState.MalformedCookie)
                {
                    // Malformed COOKIE option => FORMERR
                    Interlocked.Increment(ref _invalidCount);
                    Interlocked.Increment(ref _malformedCount);
                    ushort udpPayload = request.EDNS?.UdpPayloadSize ?? udpPayloadSizeFallback;
                    EDnsHeaderFlags flags = request.EDNS?.Flags ?? EDnsHeaderFlags.None;

                    DnsDatagram formErr = BuildCookieResponse(request, request.OPCODE, DnsResponseCode.FormatError,
                        isRecursionAllowed, request.EDNS is null ? ushort.MinValue : udpPayload, flags);

                    return CookiePreflightResult.Immediate(formErr);
                }

                // CC-only: valid request; we'll attach SC to the normal response later (no extra RTT).
                if (classification.State == CookieRequestState.ClientOnly)
                {
                    Interlocked.Increment(ref _clientOnlyCount);
                }
                else if (classification.State == CookieRequestState.InvalidServerCookie)
                {
                    // TCP can safely process an ordinary query and return a fresh cookie.
                    // UDP, and the transport-independent zero-question acquisition
                    // mechanism, use BADCOOKIE as required by RFC 7873.
                    if (IsUdpTransport(protocol) || isCookieAcquisitionRequest)
                    {
                        return CookiePreflightResult.Immediate(
                            HandleInvalidCookieRequest(request, cookieClientAddress, isRecursionAllowed, requestCookie, cookieRuntimeState));
                    }

                    Interlocked.Increment(ref _invalidCount);
                }
                else
                {
                    Interlocked.Increment(ref _validCount);
                    if (classification.ValidationResult == DnsCookieValidationResult.ValidRenew)
                        Interlocked.Increment(ref _validRenewCount);
                    else
                        Interlocked.Increment(ref _validCurrentCount);
                }
            }

            if (!isCookieAcquisitionRequest)
                return CookiePreflightResult.None;

            // Do not pass an RFC 7873 zero-question exchange to normal QUERY
            // processing, which correctly rejects all other QDCOUNT != 1 queries.
            DnsDatagram ack = BuildAcquisitionAcknowledgement(request, isRecursionAllowed);

            return CookiePreflightResult.Acquisition(ack);
        }

        /// <summary>
        /// Creates the recovery response used only when the early UDP reflection limiter elects
        /// to slip an otherwise unverified request. A usable Client Cookie receives BADCOOKIE
        /// plus an Active-secret Server Cookie; requests without usable Cookie material leave
        /// truncation construction to the transport path.
        /// </summary>
        internal DnsDatagram CreateUdpReflectionLimiterSlipResponse(DnsDatagram request, IPAddress cookieClientAddress,
            bool isRecursionAllowed, in CookieRequestClassification classification)
        {
            if (classification.RuntimeState is not EnabledState cookieRuntimeState ||
                classification.Cookie is not EDnsCookieOptionData requestCookie ||
                requestCookie.ClientCookie.Length != ClientCookieLength)
            {
                return null;
            }

            if (classification.State == CookieRequestState.ClientOnly && IsCookieAcquisitionRequest(request, classification.State))
            {
                DnsDatagram acquisition = BuildAcquisitionAcknowledgement(request, isRecursionAllowed);

                return AttachToResponse(request, acquisition, cookieClientAddress, DnsTransportProtocol.Udp, classification);
            }

            if (classification.State != CookieRequestState.ClientOnly &&
                classification.State != CookieRequestState.InvalidServerCookie)
            {
                return null;
            }

            byte[] serverCookie = cookieRuntimeState.Validator.CreateResponseCookie(cookieClientAddress, requestCookie.ClientCookie);
            EDnsCookieOptionData responseCookie = new EDnsCookieOptionData(requestCookie.ClientCookie.ToArray(), serverCookie);
            return BuildBadCookieResponse(request, isRecursionAllowed, responseCookie);
        }

        /// <summary>
        /// Attaches a Server Cookie to an already-built response when the request warrants one.
        /// Returns the original response unchanged when there is nothing to attach.
        /// </summary>
        internal DnsDatagram AttachToResponse(DnsDatagram request, DnsDatagram response, IPAddress cookieClientAddress, DnsTransportProtocol protocol,
            in CookieRequestClassification classification)
        {
            if (!SupportsDnsCookies(protocol) || classification.RuntimeState is not EnabledState cookieRuntimeState || request.EDNS is null)
                return response;

            EDnsCookieOptionData requestCookie = classification.Cookie;
            EDnsCookieOptionData responseCookie;

            if (requestCookie is not null && requestCookie.ClientCookie.Length == ClientCookieLength)
            {
                if (classification.State == CookieRequestState.ValidServerCookie &&
                    classification.ValidationResult == DnsCookieValidationResult.Valid)
                {
                    // A current RFC 9018 cookie remains bound to this client and may be
                    // echoed. ValidRenew deliberately generates with the active secret.
                    responseCookie = requestCookie;
                }
                else
                {
                    byte[] serverCookie = cookieRuntimeState.Validator.CreateResponseCookie(cookieClientAddress, requestCookie.ClientCookie);
                    responseCookie = new EDnsCookieOptionData(requestCookie.ClientCookie.ToArray(), serverCookie);
                }
            }
            else if (requestCookie is null && HasCookieOption(request))
            {
                // A COOKIE option that never parsed is dropped from the response rather
                // than echoed back.
                responseCookie = null;
            }
            else
            {
                return response;
            }

            IReadOnlyList<EDnsOption> mergedOptions =
                MergeCookieOption(response.EDNS?.Options ?? request.EDNS?.Options, responseCookie);

            return response.Clone(additional: UpsertOptRecord(response.Additional, request, response, mergedOptions));
        }

        private DnsDatagram HandleInvalidCookieRequest(DnsDatagram request, IPAddress cookieClientAddress, bool isRecursionAllowed,
            EDnsCookieOptionData requestCookie, EnabledState runtimeState)
        {
            Interlocked.Increment(ref _invalidCount);

            byte[] serverCookie = runtimeState.Validator.CreateResponseCookie(cookieClientAddress, requestCookie.ClientCookie);
            EDnsCookieOptionData responseCookie = new EDnsCookieOptionData(requestCookie.ClientCookie.ToArray(), serverCookie);

            Interlocked.Increment(ref _badCookieSentCount);

            return BuildBadCookieResponse(request, isRecursionAllowed, responseCookie);
        }

        private static DnsDatagram BuildBadCookieResponse(DnsDatagram request, bool isRecursionAllowed, EDnsCookieOptionData responseCookie)
        {
            IReadOnlyList<EDnsOption> options =
                MergeCookieOption(request.EDNS?.Options, responseCookie);

            // BADCOOKIE is a COOKIE protocol retry signal, not an RRL slip or DNS
            // truncation response, which is why nothing here sets TC. Reflection RRL may
            // independently drop the unverified UDP request before this response is emitted.
            return BuildCookieResponse(request, request.OPCODE, DnsResponseCode.BADCOOKIE, isRecursionAllowed,
                request.EDNS?.UdpPayloadSize ?? 512, request.EDNS?.Flags ?? EDnsHeaderFlags.None, options);
        }

        /// <summary>
        /// RFC 7873 section 5.4 zero-question acknowledgement used to hand a client a fresh
        /// Server Cookie without running the query.
        /// </summary>
        private static DnsDatagram BuildAcquisitionAcknowledgement(DnsDatagram request, bool isRecursionAllowed)
        {
            return BuildCookieResponse(request, DnsOpcode.StandardQuery, DnsResponseCode.NoError,
                isRecursionAllowed, request.EDNS.UdpPayloadSize, request.EDNS.Flags);
        }

        /// <summary>
        /// Builds a cookie-subsystem response that mirrors the request's identity and flags.
        /// Every such response is authoritative, never truncated, and carries no records, so
        /// only the opcode, RCODE, EDNS envelope and options differ between call sites.
        /// </summary>
        private static DnsDatagram BuildCookieResponse(DnsDatagram request, DnsOpcode opcode, DnsResponseCode rcode,
            bool isRecursionAllowed, ushort udpPayloadSize, EDnsHeaderFlags ednsFlags, IReadOnlyList<EDnsOption> options = null)
        {
            return new DnsDatagram(
                request.Identifier,
                true,
                opcode,
                authoritativeAnswer: false,
                truncation: false,
                recursionDesired: request.RecursionDesired,
                recursionAvailable: isRecursionAllowed,
                authenticData: false,
                checkingDisabled: request.CheckingDisabled,
                rcode,
                request.Question,
                null,
                null,
                null,
                udpPayloadSize,
                ednsFlags,
                options)
            { Tag = DnsServerResponseType.Authoritative };
        }

        private static IReadOnlyList<EDnsOption> MergeCookieOption(IReadOnlyList<EDnsOption> existing, EDnsCookieOptionData cookieData)
        {
            List<EDnsOption> list;

            if (existing == null)
            {
                list = new List<EDnsOption>(cookieData is null ? 0 : 1);
            }
            else
            {
                list = new List<EDnsOption>(existing.Count + 1);
                foreach (EDnsOption opt in existing)
                {
                    if (opt.Code != EDnsOptionCode.COOKIE)
                        list.Add(opt);
                }
            }

            if (cookieData is not null)
                list.Add(new EDnsOption(EDnsOptionCode.COOKIE, cookieData));

            return list;
        }

        private static IReadOnlyList<DnsResourceRecord> UpsertOptRecord(IReadOnlyList<DnsResourceRecord> existingAdditional, DnsDatagram request,
            DnsDatagram response, IReadOnlyList<EDnsOption> options)
        {
            // Build downstream OPT from request EDNS first so advertised UDP payload reflects
            // what the client can receive (do not up-advertise from upstream recursive response EDNS).
            DnsDatagramEdns baseEdns = request.EDNS ?? response.EDNS;

            ushort udp = baseEdns?.UdpPayloadSize ?? 512;
            EDnsHeaderFlags flags = baseEdns?.Flags ?? EDnsHeaderFlags.None;

            DnsResourceRecord opt = DnsDatagramEdns.GetOPTFor(
                udpPayloadSize: udp,
                extendedRCODE: response.RCODE,
                version: 0,
                flags: flags,
                options: options);

            int capacity = (existingAdditional?.Count ?? 0) + 1;
            List<DnsResourceRecord> list = new List<DnsResourceRecord>(capacity);
            foreach (DnsResourceRecord rr in existingAdditional ?? Array.Empty<DnsResourceRecord>())
            {
                if (rr.Type != DnsResourceRecordType.OPT)
                    list.Add(rr);
            }

            list.Add(opt);

            return list;
        }

        private static bool HasCookieOption(DnsDatagram request)
        {
            if (request.EDNS is null)
                return false;

            foreach (EDnsOption opt in request.EDNS.Options)
            {
                if (opt.Code == EDnsOptionCode.COOKIE)
                    return true;
            }

            return false;
        }

        private static bool IsUdpTransport(DnsTransportProtocol protocol)
        {
            return protocol == DnsTransportProtocol.Udp || protocol == DnsTransportProtocol.UdpProxy;
        }

        private static bool SupportsDnsCookies(DnsTransportProtocol protocol)
        {
            return IsUdpTransport(protocol) ||
                protocol == DnsTransportProtocol.Tcp ||
                protocol == DnsTransportProtocol.TcpProxy;
        }

        private static bool IsCookieAcquisitionRequest(DnsDatagram request, CookieRequestState cookieState)
        {
            // RFC 7873 section 5.4 permits a COOKIE option in a QUERY with no
            // question as a lightweight way to acquire or refresh a Server Cookie.
            return request.OPCODE == DnsOpcode.StandardQuery &&
                request.Question.Count == 0 &&
                (cookieState == CookieRequestState.ClientOnly ||
                 cookieState == CookieRequestState.InvalidServerCookie ||
                 cookieState == CookieRequestState.ValidServerCookie);
        }

        #endregion

        #region runtime state

        internal abstract class RuntimeState
        {
            protected RuntimeState(long generation) => Generation = generation;
            public long Generation { get; }
        }

        internal sealed class EnabledState : RuntimeState
        {
            public EnabledState(long generation, DnsCookieSecretManager secretManager)
                : base(generation)
            {
                SecretManager = secretManager;
                Validator = new DnsCookieValidator(secretManager);
            }

            public DnsCookieSecretManager SecretManager { get; }
            public DnsCookieValidator Validator { get; }
        }

        internal sealed class DisabledState : RuntimeState
        {
            public static readonly DisabledState Instance = new DisabledState();
            private DisabledState() : base(0) { }
        }

        internal sealed class DegradedState : RuntimeState
        {
            public DegradedState(long generation) : base(generation) { }
        }

        #endregion
    }
}
