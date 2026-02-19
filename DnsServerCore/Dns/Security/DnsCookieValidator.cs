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
using TechnitiumLibrary.Net.Dns.EDnsOptions;

namespace DnsServerCore.Dns.Security
{
    public sealed class DnsCookieValidator
    {
        #region constants

        // RFC 9018 v1 server cookie structure: Version(1) + Reserved(1) + Timestamp(4) + Hash(8) = 14 bytes
        const int ClientCookieLen = 8;
        const int ServerCookieLen = 14;
        const int TimestampOffset = 2;
        const int TimestampLen = 4;
        const int MacOffset = 6;
        const int MacLen = 8;

        // RFC 9018 recommends a short lifetime; 5 minutes is commonly used.
        const uint MaxSkewSeconds = 300;

        // Operational minimum; adjust to your key-management policy.
        const int MinSecretLen = 16;

        #endregion

        #region variables

        readonly DnsCookieSecretManager _secretManager;

        #endregion

        #region constructor

        public DnsCookieValidator(DnsCookieSecretManager secretManager)
        {
            _secretManager = secretManager ?? throw new ArgumentNullException(nameof(secretManager));
        }

        #endregion

        #region private helpers

        private static IPAddress CanonicalizeClientAddress(IPAddress clientAddress)
        {
            if (clientAddress is null)
                throw new ArgumentNullException(nameof(clientAddress));

            if (clientAddress.AddressFamily != AddressFamily.InterNetwork &&
                clientAddress.AddressFamily != AddressFamily.InterNetworkV6)
                throw new ArgumentException("Client address must be IPv4 or IPv6.", nameof(clientAddress));

            // Avoid representation-dependent MACs.
            if (clientAddress.IsIPv4MappedToIPv6)
                return clientAddress.MapToIPv4();

            return clientAddress;
        }

        private static void ValidateSecret(byte[] secret)
        {
            if (secret is null)
                throw new ArgumentNullException(nameof(secret));

            if (secret.Length < MinSecretLen)
                throw new ArgumentException($"Secret must be at least {MinSecretLen} bytes.", nameof(secret));
        }

        private static byte[] ComputeServerCookie(IPAddress clientAddress, ReadOnlySpan<byte> clientCookie, byte[] secret)
        {
            clientAddress = CanonicalizeClientAddress(clientAddress);
            ValidateSecret(secret);

            if (clientCookie.Length != ClientCookieLen)
                throw new ArgumentException($"Client cookie must be {ClientCookieLen} bytes.", nameof(clientCookie));

            // We must return a heap array anyway, so build directly into it.
            byte[] cookie = new byte[ServerCookieLen];
            cookie[0] = 1; // Version
            cookie[1] = 0; // Reserved

            uint ts = unchecked((uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            BinaryPrimitives.WriteUInt32BigEndian(cookie.AsSpan(TimestampOffset, TimestampLen), ts);

            // HMAC input: version | reserved | timestamp(4) | client_cookie(8) | client_ip(4/16)
            byte[] ipBytes = clientAddress.GetAddressBytes();
            int inputLen = 1 + 1 + TimestampLen + ClientCookieLen + ipBytes.Length;

            byte[] input = GC.AllocateUninitializedArray<byte>(inputLen);
            input[0] = cookie[0];
            input[1] = cookie[1];
            cookie.AsSpan(TimestampOffset, TimestampLen).CopyTo(input.AsSpan(2, TimestampLen));
            clientCookie.CopyTo(input.AsSpan(2 + TimestampLen));
            ipBytes.AsSpan().CopyTo(input.AsSpan(2 + TimestampLen + ClientCookieLen));

            Span<byte> fullMac = stackalloc byte[32];
            HMACSHA256.HashData(secret, input, fullMac);

            fullMac.Slice(0, MacLen).CopyTo(cookie.AsSpan(MacOffset, MacLen));
            return cookie;
        }

        private static bool ValidateServerCookieWithSecret(
            IPAddress clientAddress,
            ReadOnlySpan<byte> clientCookie,
            ReadOnlySpan<byte> serverCookie,
            byte[] secret)
        {
            if (clientAddress is null || secret is null)
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

            if (clientAddress.IsIPv4MappedToIPv6)
                clientAddress = clientAddress.MapToIPv4();

            // Version must match v1
            if (serverCookie[0] != 1)
                return false;

            // Reserved; strict since we always emit 0 (change to "ignore" if you want forward-compat)
            if (serverCookie[1] != 0)
                return false;

            uint cookieTs = BinaryPrimitives.ReadUInt32BigEndian(serverCookie.Slice(TimestampOffset, TimestampLen));
            uint nowTs = unchecked((uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds());

            uint diff = nowTs >= cookieTs ? (nowTs - cookieTs) : (cookieTs - nowTs);
            if (diff > MaxSkewSeconds)
                return false;

            // Recompute expected MAC over exact bytes: version|reserved|timestampBytes|clientCookie|clientIP
            byte[] ipBytes = clientAddress.GetAddressBytes();
            int inputLen = 1 + 1 + TimestampLen + ClientCookieLen + ipBytes.Length;

            byte[] input = GC.AllocateUninitializedArray<byte>(inputLen);
            input[0] = serverCookie[0];
            input[1] = serverCookie[1];
            serverCookie.Slice(TimestampOffset, TimestampLen).CopyTo(input.AsSpan(2, TimestampLen));
            clientCookie.CopyTo(input.AsSpan(2 + TimestampLen));
            ipBytes.AsSpan().CopyTo(input.AsSpan(2 + TimestampLen + ClientCookieLen));

            Span<byte> fullMac = stackalloc byte[32];
            HMACSHA256.HashData(secret, input, fullMac);

            ReadOnlySpan<byte> provided = serverCookie.Slice(MacOffset, MacLen);
            Span<byte> expected = fullMac.Slice(0, MacLen);

            return CryptographicOperations.FixedTimeEquals(expected, provided);
        }

        #endregion

        #region public

        public bool Validate(IPAddress clientAddress, EDnsCookieOptionData cookie)
        {
            if (clientAddress is null || cookie is null)
                return false;

            // This validator is specifically for validating presence of BOTH CC and SC.
            if (cookie.ClientCookie.IsEmpty || cookie.ServerCookie.IsEmpty)
                return false;

            if (cookie.ClientCookie.Length != ClientCookieLen)
                return false;

            byte[] currentSecret = _secretManager.GetCurrentSecret();
            if (currentSecret != null &&
                ValidateServerCookieWithSecret(clientAddress, cookie.ClientCookie, cookie.ServerCookie, currentSecret))
                return true;

            byte[] previousSecret = _secretManager.GetPreviousSecret();
            if (previousSecret != null &&
                ValidateServerCookieWithSecret(clientAddress, cookie.ClientCookie, cookie.ServerCookie, previousSecret))
                return true;

            return false;
        }

        public EDnsCookieOptionData CreateResponseCookie(IPAddress clientAddress, EDnsCookieOptionData requestCookie)
        {
            if (clientAddress is null)
                throw new ArgumentNullException(nameof(clientAddress));

            if (requestCookie is null || requestCookie.ClientCookie.IsEmpty)
                throw new ArgumentException("Request cookie must include a client cookie.", nameof(requestCookie));

            if (requestCookie.ClientCookie.Length != ClientCookieLen)
                throw new ArgumentException($"Client cookie must be {ClientCookieLen} bytes.", nameof(requestCookie));

            byte[] currentSecret = _secretManager.GetCurrentSecret();
            ValidateSecret(currentSecret);

            byte[] serverCookie = ComputeServerCookie(clientAddress, requestCookie.ClientCookie, currentSecret);
            return new EDnsCookieOptionData(requestCookie.ClientCookie.ToArray(), serverCookie);
        }

        #endregion
    }
}
