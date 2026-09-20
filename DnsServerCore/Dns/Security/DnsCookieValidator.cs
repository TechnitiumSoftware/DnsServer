/*
Technitium DNS Server
Copyright (C) 2026 Shreyas Zare (shreyas@technitium.com)

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
using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Threading;

namespace DnsServerCore.Dns.Security
{
    public enum DnsCookieValidationResult
    {
        Invalid,
        Valid,
        ValidRenew
    }

    public sealed class DnsCookieValidator
    {
        #region constants

        // RFC 9018 v1 server cookie structure: Version(1) + Reserved(3) + Timestamp(4) + Hash(8) = 16 bytes
        const int ClientCookieLen = 8;
        const int ServerCookieLen = 16;

        const int VersionOffset = 0;
        const int ReservedOffset = 1;
        const int ReservedLen = 3;

        const int TimestampOffset = 4;
        const int TimestampLen = 4;

        const int MacOffset = 8;
        const int MacLen = 8;

        const byte Version1 = 1;

        // RFC 9018 recommended acceptance: <= 1 hour past, <= 5 minutes future
        const uint MaxPastSeconds = 3600;
        const uint MaxFutureSeconds = 300;

        // RFC 9018 Version 1 uses SipHash-2-4 with one canonical 128-bit key.
        const int SecretLength = 16;

        // clientCookie(8) | version(1) | reserved(3) | timestamp(4) | clientIP(4 or 16)
        const int MaxMacInputLength = ClientCookieLen + 1 + ReservedLen + TimestampLen + AddressPrefix.MaximumAddressLength;

        #endregion

        #region variables

        readonly byte[] _activeSecret;
        readonly byte[] _stagingSecret;
        readonly byte[] _previousSecret;
        readonly TimeProvider _timeProvider;

        #endregion

        #region constructor

        public DnsCookieValidator(DnsCookieSecretManager secretManager, TimeProvider timeProvider = null)
        {
            ArgumentNullException.ThrowIfNull(secretManager);
            secretManager.GetSecrets(out _activeSecret, out _stagingSecret, out _previousSecret);
            _timeProvider = timeProvider ?? TimeProvider.System;
        }

        #endregion

        #region private helpers

        private static bool IsUsableSecret(ReadOnlySpan<byte> secret) => secret.Length == SecretLength;

        private uint GetCurrentUnixTimeSeconds()
        {
            long unixTimeSeconds = ReferenceEquals(_timeProvider, TimeProvider.System)
                ? CachedSystemTime.UnixTimeSeconds
                : _timeProvider.GetUtcNow().ToUnixTimeSeconds();

            return unchecked((uint)unixTimeSeconds);
        }

        private static class CachedSystemTime
        {
            private static long s_unixTimeSeconds = TimeProvider.System.GetUtcNow().ToUnixTimeSeconds();
            private static readonly Timer s_refreshTimer = new Timer(
                static _ => Interlocked.Exchange(ref s_unixTimeSeconds, TimeProvider.System.GetUtcNow().ToUnixTimeSeconds()),
                null,
                TimeSpan.FromMilliseconds(10),
                TimeSpan.FromMilliseconds(10));

            public static long UnixTimeSeconds => Interlocked.Read(ref s_unixTimeSeconds);
        }

        /// <summary>
        /// Builds the RFC 9018 MAC input and tags it. Construction and verification both go
        /// through here so the two can never disagree about the byte layout or about how a
        /// client address is canonicalized - a disagreement would silently reject every cookie
        /// this server issued.
        /// </summary>
        private static ulong ComputeTag(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> clientCookie, byte version,
            ReadOnlySpan<byte> reserved, ReadOnlySpan<byte> timestamp, ReadOnlySpan<byte> canonicalAddress)
        {
            Span<byte> input = stackalloc byte[MaxMacInputLength];
            int o = 0;
            clientCookie.CopyTo(input[o..]); o += ClientCookieLen;
            input[o++] = version;
            reserved.CopyTo(input[o..]); o += ReservedLen;
            timestamp.CopyTo(input[o..]); o += TimestampLen;
            canonicalAddress.CopyTo(input[o..]); o += canonicalAddress.Length;

            return SipHash24.Compute(secret, input[..o]);
        }

        private byte[] ComputeServerCookie(IPAddress clientAddress, ReadOnlySpan<byte> clientCookie, ReadOnlySpan<byte> secret)
        {
            ArgumentNullException.ThrowIfNull(clientAddress);

            if (!IsUsableSecret(secret))
                throw new ArgumentException($"Secret must be exactly {SecretLength} bytes.", nameof(secret));

            if (clientCookie.Length != ClientCookieLen)
                throw new ArgumentException($"Client cookie must be {ClientCookieLen} bytes.", nameof(clientCookie));

            Span<byte> address = stackalloc byte[AddressPrefix.MaximumAddressLength];
            if (!AddressPrefix.TryWriteCanonical(clientAddress, address, out int addressLength, out _))
                throw new ArgumentException("Client address must be IPv4 or IPv6.", nameof(clientAddress));

            byte[] cookie = new byte[ServerCookieLen];

            cookie[VersionOffset] = Version1;

            // Reserved MUST be set to zero on construction (RFC 9018)
            cookie.AsSpan(ReservedOffset, ReservedLen).Clear();

            BinaryPrimitives.WriteUInt32BigEndian(cookie.AsSpan(TimestampOffset, TimestampLen), GetCurrentUnixTimeSeconds());

            ulong tag = ComputeTag(secret, clientCookie, cookie[VersionOffset], cookie.AsSpan(ReservedOffset, ReservedLen),
                cookie.AsSpan(TimestampOffset, TimestampLen), address[..addressLength]);

            // SipHash's octet output is the little-endian serialization of the ulong result.
            BinaryPrimitives.WriteUInt64LittleEndian(cookie.AsSpan(MacOffset, MacLen), tag);

            return cookie;
        }

        private bool IsTimestampAcceptable(uint cookieTs)
        {
            uint nowTs = GetCurrentUnixTimeSeconds();

            // RFC 1982 serial arithmetic
            static bool SerialLessThan(uint a, uint b) => a != b && (uint)(b - a) < 0x8000_0000u;

            return SerialLessThan(nowTs, cookieTs)
                ? unchecked(cookieTs - nowTs) <= MaxFutureSeconds
                : unchecked(nowTs - cookieTs) <= MaxPastSeconds;
        }

        private bool ValidateServerCookieWithSecret(IPAddress clientAddress, ReadOnlySpan<byte> clientCookie,
            ReadOnlySpan<byte> serverCookie, ReadOnlySpan<byte> secret)
        {
            if (!IsUsableSecret(secret) || clientCookie.Length != ClientCookieLen || serverCookie.Length != ServerCookieLen)
                return false;

            if (serverCookie[VersionOffset] != Version1)
                return false;

            Span<byte> address = stackalloc byte[AddressPrefix.MaximumAddressLength];
            if (!AddressPrefix.TryWriteCanonical(clientAddress, address, out int addressLength, out _))
                return false;

            if (!IsTimestampAcceptable(BinaryPrimitives.ReadUInt32BigEndian(serverCookie.Slice(TimestampOffset, TimestampLen))))
                return false;

            // IMPORTANT (RFC 9018): do NOT enforce Reserved==0 on verification.
            // Include received reserved bytes in the MAC input.
            ulong expectedTag = ComputeTag(secret, clientCookie, serverCookie[VersionOffset],
                serverCookie.Slice(ReservedOffset, ReservedLen), serverCookie.Slice(TimestampOffset, TimestampLen),
                address[..addressLength]);

            // Constant-time compare without allocating:
            // compare tags by bytes, not by ulong equality (avoids timing artifacts)
            Span<byte> expectedBytes = stackalloc byte[MacLen];
            BinaryPrimitives.WriteUInt64LittleEndian(expectedBytes, expectedTag);
            return CryptographicOperations.FixedTimeEquals(expectedBytes, serverCookie.Slice(MacOffset, MacLen));
        }

        #endregion

        #region public

        public DnsCookieValidationResult Validate(IPAddress clientAddress, ReadOnlySpan<byte> clientCookie, ReadOnlySpan<byte> serverCookie)
        {
            // This validator is specifically for validating presence of BOTH CC and SC.
            if (clientAddress is null || clientCookie.Length != ClientCookieLen || serverCookie.IsEmpty)
                return DnsCookieValidationResult.Invalid;

            if (ValidateServerCookieWithSecret(clientAddress, clientCookie, serverCookie, _activeSecret))
                return DnsCookieValidationResult.Valid;

            // A cookie still carrying the staged or previous secret is honoured, but the caller
            // is told to reissue it against the active secret.
            if (ValidateServerCookieWithSecret(clientAddress, clientCookie, serverCookie, _stagingSecret) ||
                ValidateServerCookieWithSecret(clientAddress, clientCookie, serverCookie, _previousSecret))
                return DnsCookieValidationResult.ValidRenew;

            return DnsCookieValidationResult.Invalid;
        }

        public byte[] CreateResponseCookie(IPAddress clientAddress, ReadOnlySpan<byte> clientCookie)
        {
            ArgumentNullException.ThrowIfNull(clientAddress);

            if (clientCookie.IsEmpty)
                throw new ArgumentException("Request cookie must include a client cookie.", nameof(clientCookie));

            if (clientCookie.Length != ClientCookieLen)
                throw new ArgumentException($"Client cookie must be {ClientCookieLen} bytes.", nameof(clientCookie));

            return ComputeServerCookie(clientAddress, clientCookie, _activeSecret);
        }

        #endregion
    }
}
