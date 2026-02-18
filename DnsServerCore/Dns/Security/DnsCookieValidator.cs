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
using System.IO;
using System.Net;
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

            using (MemoryStream ms = new MemoryStream())
            {
                using (BinaryWriter bw = new BinaryWriter(ms))
                {
                    // Version 1
                    bw.Write((byte)1);

                    // Reserved (0)
                    bw.Write((byte)0);

                    // Timestamp (Unix time in seconds)
                    uint timestamp = (uint)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() & 0xFFFFFFFF);
                    bw.Write(timestamp);

                    // Compute HMAC-SHA256 hash
                    byte[] hashInput;
                    using (MemoryStream hashMs = new MemoryStream())
                    {
                        using (BinaryWriter hashBw = new BinaryWriter(hashMs))
                        {
                            // Hash input: version | reserved | timestamp | client_cookie | client_ip
                            hashBw.Write((byte)1);
                            hashBw.Write((byte)0);
                            hashBw.Write(timestamp);
                            hashBw.Write(clientCookie);
                            hashBw.Write(clientAddress.GetAddressBytes());
                        }
                        hashInput = hashMs.ToArray();
                    }

                    using (HMACSHA256 hmac = new HMACSHA256(secret))
                    {
                        byte[] hash = hmac.ComputeHash(hashInput);
                        // Take first 8 bytes (64 bits) as per RFC 9018
                        bw.Write(hash, 0, 8);
                    }
                }

                return ms.ToArray();
            }
        }

        private static bool ValidateServerCookieWithSecret(IPAddress clientAddress, ReadOnlySpan<byte> clientCookie, ReadOnlySpan<byte> serverCookie, byte[] secret)
        {
            if (serverCookie.Length < 8 || serverCookie.Length > 32)
                return false;

            // Extract timestamp from server cookie
            if (serverCookie.Length < 6)
                return false;

            byte version = serverCookie[0];
            if (version != 1)
                return false;

            uint cookieTimestamp = BitConverter.ToUInt32(serverCookie.ToArray(), 2);
            uint currentTimestamp = (uint)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() & 0xFFFFFFFF);

            // Check timestamp is within 5 minutes (300 seconds) - RFC 9018 recommendation
            uint timeDiff = currentTimestamp > cookieTimestamp 
                ? currentTimestamp - cookieTimestamp 
                : cookieTimestamp - currentTimestamp;

            if (timeDiff > 300)
                return false;

            // Recompute hash with the same timestamp
            using (MemoryStream hashMs = new MemoryStream())
            {
                using (BinaryWriter hashBw = new BinaryWriter(hashMs))
                {
                    hashBw.Write((byte)1);
                    hashBw.Write((byte)0);
                    hashBw.Write(cookieTimestamp);
                    hashBw.Write(clientCookie);
                    hashBw.Write(clientAddress.GetAddressBytes());
                }

                using (HMACSHA256 hmac = new HMACSHA256(secret))
                {
                    byte[] hash = hmac.ComputeHash(hashMs.ToArray());
                    
                    // Compare first 8 bytes
                    if (serverCookie.Length >= 14)
                    {
                        for (int i = 0; i < 8; i++)
                        {
                            if (serverCookie[6 + i] != hash[i])
                                return false;
                        }
                        return true;
                    }
                }
            }

            return false;
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
