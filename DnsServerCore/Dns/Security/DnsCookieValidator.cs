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
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using TechnitiumLibrary.Net.Dns.EDnsOptions;

namespace DnsServerCore.Dns.Security
{
    public class DnsCookieValidator
    {
        #region variables

        readonly DnsCookieSecretManager _secretManager;
        // RFC 9018 server cookie structure: Version(1) + Reserved(1) + Timestamp(4) + Hash(8) = 14 bytes

        #endregion

        #region constructor

        public DnsCookieValidator(DnsCookieSecretManager secretManager)
        {
            _secretManager = secretManager ?? throw new ArgumentNullException(nameof(secretManager));
        }

        #endregion

        #region private

        private static byte[] ComputeServerCookie(IPAddress clientAddress, ReadOnlySpan<byte> clientCookie, byte[] secret)
        {
            // RFC 9018 server cookie structure:
            // Version (1 byte) | Reserved (1 byte) | Timestamp (4 bytes) | Hash (8 bytes)
            const int CookieLen = 14;

            if (clientAddress is null)
                throw new ArgumentNullException(nameof(clientAddress));

            if (secret is null)
                throw new ArgumentNullException(nameof(secret));

            // Operationally sane minimum (adjust to your key management policy)
            if (secret.Length < 16)
                throw new ArgumentException("Secret must be at least 16 bytes.", nameof(secret));

            // COOKIE option client cookie is commonly 8 bytes; RFC allows a range.
            // Keep bounds strict enough to prevent abuse but aligned to what you support.
            const int MinClientCookieLen = 8;
            const int MaxClientCookieLen = 32; // adjust if your implementation supports a different maximum

            if (clientCookie.Length < MinClientCookieLen || clientCookie.Length > MaxClientCookieLen)
                throw new ArgumentOutOfRangeException(
                    nameof(clientCookie),
                    $"Client cookie length must be between {MinClientCookieLen} and {MaxClientCookieLen} bytes.");

            // Only IPv4/IPv6 are meaningful here
            if (clientAddress.AddressFamily != AddressFamily.InterNetwork &&
                clientAddress.AddressFamily != AddressFamily.InterNetworkV6)
                throw new ArgumentException("Client address must be IPv4 or IPv6.", nameof(clientAddress));

            // Canonicalize IPv4-mapped IPv6 to IPv4 to avoid representation-dependent MACs
            if (clientAddress.IsIPv4MappedToIPv6)
                clientAddress = clientAddress.MapToIPv4();

            Span<byte> cookie = stackalloc byte[CookieLen];
            cookie[0] = 1; // Version
            cookie[1] = 0; // Reserved

            uint ts = unchecked((uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            BinaryPrimitives.WriteUInt32BigEndian(cookie.Slice(2, 4), ts);

            // Build HMAC input
            byte[] ipBytes = clientAddress.GetAddressBytes();
            int inputLen = 1 + 1 + 4 + clientCookie.Length + ipBytes.Length;

            // Defensive ceiling against pathological sizes (should never trigger with sane bounds)
            const int MaxInputLen = 1 + 1 + 4 + MaxClientCookieLen + 16; // v6 worst case
            if (inputLen > MaxInputLen)
                throw new InvalidOperationException("Computed hash input length exceeds expected maximum.");

            byte[] input = GC.AllocateUninitializedArray<byte>(inputLen);
            input[0] = 1;
            input[1] = 0;
            cookie.Slice(2, 4).CopyTo(input.AsSpan(2, 4));
            clientCookie.CopyTo(input.AsSpan(6));
            ipBytes.AsSpan().CopyTo(input.AsSpan(6 + clientCookie.Length));

            // Compute MAC
            Span<byte> fullMac = stackalloc byte[32];
            HMACSHA256.HashData(secret, input, fullMac);

            // First 8 bytes (64 bits)
            fullMac.Slice(0, 8).CopyTo(cookie.Slice(6, 8));

            return cookie.ToArray();
        }

        private static bool ValidateServerCookieWithSecret(
            IPAddress clientAddress,
            ReadOnlySpan<byte> clientCookie,
            ReadOnlySpan<byte> serverCookie,
            byte[] secret)
        {
            if (clientAddress is null || secret is null)
                return false;

            // Server cookie v1 structure is fixed 14 bytes in this implementation.
            if (serverCookie.Length != 14)
                return false;

            // Client cookie is fixed 8 bytes by your public Validate() already,
            // but keep it defensive here too.
            if (clientCookie.Length != 8)
                return false;

            // Version / reserved
            if (serverCookie[0] != 1)
                return false;

            // enforce reserved == 0 (you always emit 0)
            if (serverCookie[1] != 0)
                return false;

            // Only IPv4/IPv6; canonicalize IPv4-mapped IPv6 to IPv4 (must match compute policy)
            if (clientAddress.AddressFamily != AddressFamily.InterNetwork &&
                clientAddress.AddressFamily != AddressFamily.InterNetworkV6)
                return false;

            if (clientAddress.IsIPv4MappedToIPv6)
                clientAddress = clientAddress.MapToIPv4();

            // Timestamp validation (big-endian)
            uint cookieTs = BinaryPrimitives.ReadUInt32BigEndian(serverCookie.Slice(2, 4));
            uint nowTs = unchecked((uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds());

            uint diff = nowTs >= cookieTs ? (nowTs - cookieTs) : (cookieTs - nowTs);
            if (diff > 300) // 5 minutes
                return false;

            // Recompute MAC over exact bytes: version|reserved|timestampBytes|clientCookie|clientIP
            byte[] ipBytes = clientAddress.GetAddressBytes();
            int inputLen = 1 + 1 + 4 + clientCookie.Length + ipBytes.Length;

            byte[] input = GC.AllocateUninitializedArray<byte>(inputLen);
            input[0] = serverCookie[0];
            input[1] = serverCookie[1];
            serverCookie.Slice(2, 4).CopyTo(input.AsSpan(2, 4));
            clientCookie.CopyTo(input.AsSpan(6));
            ipBytes.AsSpan().CopyTo(input.AsSpan(6 + clientCookie.Length));

            Span<byte> fullMac = stackalloc byte[32];
            HMACSHA256.HashData(secret, input, fullMac);

            // Compare first 8 bytes in constant time
            Span<byte> expected = fullMac.Slice(0, 8);
            ReadOnlySpan<byte> provided = serverCookie.Slice(6, 8);

            return CryptographicOperations.FixedTimeEquals(expected, provided);
        }

        #endregion

        #region public

        public bool Validate(IPAddress clientAddress, EDnsCookieOptionData cookie)
        {
            if (cookie == null || cookie.ClientCookie.IsEmpty || cookie.ServerCookie.IsEmpty)
                return false;

            if (cookie.ClientCookie.Length != 8)
                return false;

            // Try current secret first
            byte[] currentSecret = _secretManager.GetCurrentSecret();
            if (currentSecret != null && ValidateServerCookieWithSecret(clientAddress, cookie.ClientCookie, cookie.ServerCookie, currentSecret))
                return true;

            // Try previous secret for rotation grace period
            byte[] previousSecret = _secretManager.GetPreviousSecret();
            if (previousSecret != null && ValidateServerCookieWithSecret(clientAddress, cookie.ClientCookie, cookie.ServerCookie, previousSecret))
                return true;

            return false;
        }

        public EDnsCookieOptionData CreateResponseCookie(IPAddress clientAddress, EDnsCookieOptionData requestCookie)
        {
            if (requestCookie == null || requestCookie.ClientCookie.IsEmpty)
                throw new ArgumentException("Request cookie must have a client cookie");

            if (requestCookie.ClientCookie.Length != 8)
                throw new ArgumentException("Client cookie must be 8 bytes");

            byte[] currentSecret = _secretManager.GetCurrentSecret();
            byte[] serverCookie = ComputeServerCookie(clientAddress, requestCookie.ClientCookie, currentSecret);

            return new EDnsCookieOptionData(requestCookie.ClientCookie.ToArray(), serverCookie);
        }

        #endregion
    }
}
