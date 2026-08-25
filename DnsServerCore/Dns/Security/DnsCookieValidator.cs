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
using System.Net.Sockets;
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

        // RFC 9018 recommended acceptance: <= 1 hour past, <= 5 minutes future
        const uint MaxPastSeconds = 3600;
        const uint MaxFutureSeconds = 300;

        // Operational minimum; adjust to your key-management policy.
        const int MinSecretLen = 16;

        #endregion

        #region variables

        readonly byte[] _activeSecret;
        readonly byte[] _stagingSecret;
        readonly TimeProvider _timeProvider;

        #endregion

        #region constructor

        public DnsCookieValidator(DnsCookieSecretManager secretManager, TimeProvider timeProvider = null)
        {
            ArgumentNullException.ThrowIfNull(secretManager);
            secretManager.GetSecrets(out _activeSecret, out _stagingSecret);
            _timeProvider = timeProvider ?? TimeProvider.System;
        }

        #endregion

        #region private helpers

        private static IPAddress CanonicalizeClientAddress(IPAddress clientAddress)
        {
            ArgumentNullException.ThrowIfNull(clientAddress);

            if (clientAddress.AddressFamily != AddressFamily.InterNetwork &&
                clientAddress.AddressFamily != AddressFamily.InterNetworkV6)
                throw new ArgumentException("Client address must be IPv4 or IPv6.", nameof(clientAddress));

            // Avoid representation-dependent MACs.
            if (clientAddress.IsIPv4MappedToIPv6)
                return clientAddress.MapToIPv4();

            return clientAddress;
        }

        private static void ValidateSecret(ReadOnlySpan<byte> secret)
        {
            if (secret.IsEmpty)
                throw new ArgumentException("Secret must not be empty.", nameof(secret));

            if (secret.Length < MinSecretLen)
                throw new ArgumentException($"Secret must be at least {MinSecretLen} bytes.", nameof(secret));
        }

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

        private byte[] ComputeServerCookie(IPAddress clientAddress, ReadOnlySpan<byte> clientCookie, ReadOnlySpan<byte> secret)
        {
            clientAddress = CanonicalizeClientAddress(clientAddress);
            ValidateSecret(secret);

            if (clientCookie.Length != ClientCookieLen)
                throw new ArgumentException($"Client cookie must be {ClientCookieLen} bytes.", nameof(clientCookie));

            byte[] cookie = new byte[ServerCookieLen];

            cookie[VersionOffset] = 1;

            // Reserved MUST be set to zero on construction (RFC 9018)
            cookie.AsSpan(ReservedOffset, ReservedLen).Clear();

            uint ts = GetCurrentUnixTimeSeconds();
            BinaryPrimitives.WriteUInt32BigEndian(cookie.AsSpan(TimestampOffset, TimestampLen), ts);

            // SipHash input: clientCookie(8) | version(1) | reserved(3) | timestamp(4) | clientIP(4/16)
            byte[] ipBytes = clientAddress.GetAddressBytes();
            int inputLen = ClientCookieLen + 1 + ReservedLen + TimestampLen + ipBytes.Length;

            Span<byte> input = inputLen <= 64 ? stackalloc byte[inputLen] : new byte[inputLen];
            int o = 0;
            clientCookie.CopyTo(input.Slice(o, ClientCookieLen)); o += ClientCookieLen;
            input[o++] = cookie[VersionOffset];
            cookie.AsSpan(ReservedOffset, ReservedLen).CopyTo(input.Slice(o, ReservedLen)); o += ReservedLen;
            cookie.AsSpan(TimestampOffset, TimestampLen).CopyTo(input.Slice(o, TimestampLen)); o += TimestampLen;
            ipBytes.AsSpan().CopyTo(input.Slice(o, ipBytes.Length));

            ReadOnlySpan<byte> key16 = secret.Slice(0, 16); // acceptable if secret is uniformly random
            ulong tag = SipHash24.Compute(key16, input);

            // SipHash's octet output is the little-endian serialization of the ulong result.
            BinaryPrimitives.WriteUInt64LittleEndian(cookie.AsSpan(MacOffset, MacLen), tag);

            return cookie;
        }

        private bool ValidateServerCookieWithSecret(
             IPAddress clientAddress,
             ReadOnlySpan<byte> clientCookie,
             ReadOnlySpan<byte> serverCookie,
             ReadOnlySpan<byte> secret)
        {
            if (clientAddress is null || secret.IsEmpty)
                return false;

            if (secret.Length < MinSecretLen)
                return false;

            if (clientCookie.Length != ClientCookieLen)
                return false;

            if (serverCookie.Length != ServerCookieLen)
                return false;

            // Canonicalize must match ComputeServerCookie policy
            if (clientAddress.AddressFamily != AddressFamily.InterNetwork &&
                clientAddress.AddressFamily != AddressFamily.InterNetworkV6)
                return false;

            if (serverCookie[VersionOffset] != 1)
                return false;

            // IMPORTANT (RFC 9018): do NOT enforce Reserved==0 on verification.
            // Include received reserved bytes in the MAC input.

            uint cookieTs = BinaryPrimitives.ReadUInt32BigEndian(serverCookie.Slice(TimestampOffset, TimestampLen));
            uint nowTs = GetCurrentUnixTimeSeconds();

            // RFC 1982 serial arithmetic
            static bool SerialLessThan(uint a, uint b) => a != b && (uint)(b - a) < 0x8000_0000u;
            static uint SerialDistance(uint a, uint b) => (uint)(b - a);

            if (SerialLessThan(nowTs, cookieTs))
            {
                uint future = SerialDistance(nowTs, cookieTs);
                if (future > MaxFutureSeconds)
                    return false;
            }
            else
            {
                uint past = SerialDistance(cookieTs, nowTs);
                if (past > MaxPastSeconds)
                    return false;
            }

            // SipHash input: clientCookie(8) | version(1) | reserved(3) | timestamp(4) | clientIP(4/16)
            Span<byte> ip = stackalloc byte[16];
            int ipLen = 0;

            // Avoid MapToIPv4() allocation: handle IPv4-mapped via bytes.
            if (clientAddress.AddressFamily == AddressFamily.InterNetwork)
            {
                ipLen = 4;
                clientAddress.TryWriteBytes(ip.Slice(0, 4), out _);
            }
            else
            {
                // IPv6
                clientAddress.TryWriteBytes(ip, out int written);
                if (written != 16)
                    return false; // or throw in compute path

                // If v4-mapped (::ffff:a.b.c.d), canonicalize to 4 bytes (last 4 bytes)
                bool isV4Mapped =
                    ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 &&
                    ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
                    ip[8] == 0 && ip[9] == 0 &&
                    ip[10] == 0xff && ip[11] == 0xff;

                if (isV4Mapped)
                {
                    ipLen = 4;
                    ip.Slice(12, 4).CopyTo(ip.Slice(0, 4));
                }
                else
                {
                    ipLen = 16;
                }
            }

            int inputLen = ClientCookieLen + 1 + ReservedLen + TimestampLen + ipLen;
            Span<byte> input = stackalloc byte[inputLen]; // always <= 32 here
            int o = 0;
            clientCookie.CopyTo(input.Slice(o, ClientCookieLen)); o += ClientCookieLen;
            input[o++] = serverCookie[VersionOffset];
            serverCookie.Slice(ReservedOffset, ReservedLen).CopyTo(input.Slice(o, ReservedLen)); o += ReservedLen;
            serverCookie.Slice(TimestampOffset, TimestampLen).CopyTo(input.Slice(o, TimestampLen)); o += TimestampLen;
            ip.Slice(0, ipLen).CopyTo(input.Slice(o, ipLen));

            ReadOnlySpan<byte> key16 = secret.Slice(0, 16);
            ulong expectedTag = SipHash24.Compute(key16, input);

            // Constant-time compare without allocating:
            // compare tags by bytes, not by ulong equality (avoids timing artifacts)
            Span<byte> expectedBytes = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64LittleEndian(expectedBytes, expectedTag);
            return CryptographicOperations.FixedTimeEquals(expectedBytes, serverCookie.Slice(MacOffset, MacLen));
        }

        #endregion

        #region public

        public DnsCookieValidationResult Validate(IPAddress clientAddress, ReadOnlySpan<byte> clientCookie, ReadOnlySpan<byte> serverCookie)
        {
            if (clientAddress is null)
                return DnsCookieValidationResult.Invalid;

            // This validator is specifically for validating presence of BOTH CC and SC.
            if (clientCookie.IsEmpty || serverCookie.IsEmpty)
                return DnsCookieValidationResult.Invalid;

            if (clientCookie.Length != ClientCookieLen)
                return DnsCookieValidationResult.Invalid;

            byte[] active = _activeSecret;

            if (active != null && active.Length > 0 &&
                ValidateServerCookieWithSecret(clientAddress, clientCookie, serverCookie, active))
                return DnsCookieValidationResult.Valid;

            byte[] staging = _stagingSecret;
            if (staging != null && staging.Length > 0 &&
                ValidateServerCookieWithSecret(clientAddress, clientCookie, serverCookie, staging))
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

            byte[] active = _activeSecret;
            ValidateSecret(active);

            return ComputeServerCookie(clientAddress, clientCookie, active);
        }

        #endregion
    }
}
