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
using System.Net;
using System.Net.Sockets;

namespace DnsServerCore.Dns.Security
{
    /// <summary>
    /// Address handling shared by the DNS Cookie and rate limiting subsystems. Both derive
    /// keys from client addresses, so both must agree on how an address becomes bytes; keeping
    /// one copy of these rules is what stops the two from drifting apart.
    /// </summary>
    internal static class AddressPrefix
    {
        internal const int MaximumAddressLength = 16;

        internal const byte IPv4FamilyCode = 4;
        internal const byte IPv6FamilyCode = 6;

        /// <summary>
        /// Zeroes every bit below <paramref name="prefixLength"/> in place. Callers validate
        /// their prefix lengths against the address size, so a prefix longer than the address
        /// is a programming error and is left to throw rather than being silently clamped.
        /// </summary>
        internal static void MaskHostBits(Span<byte> address, int prefixLength)
        {
            int wholeBytes = prefixLength / 8;
            int remainingBits = prefixLength % 8;

            if (remainingBits != 0 && wholeBytes < address.Length)
            {
                address[wholeBytes] &= (byte)(0xff << (8 - remainingBits));
                wholeBytes++;
            }

            address[wholeBytes..].Clear();
        }

        /// <summary>
        /// Writes the canonical byte form of <paramref name="address"/>: four bytes for IPv4
        /// and for IPv4-mapped IPv6, sixteen for any other IPv6. Collapsing the mapped form
        /// keeps one client from presenting as two identities depending on how the socket
        /// surfaced its address, which would otherwise let the same peer hold two cookie
        /// identities or two rate limiter buckets.
        /// </summary>
        /// <param name="destination">Receives the address bytes; must be at least 16 bytes long.</param>
        /// <returns><see langword="false"/> for anything that is not IPv4 or IPv6.</returns>
        internal static bool TryWriteCanonical(IPAddress address, Span<byte> destination, out int length, out byte familyCode)
        {
            length = 0;
            familyCode = 0;

            if (address is null)
                return false;

            switch (address.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    if (!address.TryWriteBytes(destination, out length) || length != 4)
                        return false;

                    familyCode = IPv4FamilyCode;
                    return true;

                case AddressFamily.InterNetworkV6:
                    if (!address.TryWriteBytes(destination, out length) || length != MaximumAddressLength)
                        return false;

                    // Match on the written bytes rather than IPAddress.IsIPv4MappedToIPv6 so
                    // the collapse costs no allocation on the packet path.
                    if (IsIPv4Mapped(destination))
                    {
                        destination.Slice(12, 4).CopyTo(destination);
                        length = 4;
                        familyCode = IPv4FamilyCode;
                        return true;
                    }

                    familyCode = IPv6FamilyCode;
                    return true;

                default:
                    return false;
            }
        }

        private static bool IsIPv4Mapped(ReadOnlySpan<byte> address)
        {
            return address[0] == 0 && address[1] == 0 && address[2] == 0 && address[3] == 0 &&
                address[4] == 0 && address[5] == 0 && address[6] == 0 && address[7] == 0 &&
                address[8] == 0 && address[9] == 0 &&
                address[10] == 0xff && address[11] == 0xff;
        }
    }
}
