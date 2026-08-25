#nullable enable

using System;
using System.Buffers.Binary;
using System.Numerics;

namespace DnsServerCore.Dns.Security
{
    /// <summary>Computes SipHash-2-4 message authentication tags.</summary>
    internal static class SipHash24
    {
        public static ulong Compute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
        {
            if (key.Length != 16)
                throw new ArgumentException("SipHash key must be 16 bytes.", nameof(key));

            ulong key0 = BinaryPrimitives.ReadUInt64LittleEndian(key);
            ulong key1 = BinaryPrimitives.ReadUInt64LittleEndian(key[8..]);
            ulong v0 = 0x736f6d6570736575UL ^ key0;
            ulong v1 = 0x646f72616e646f6dUL ^ key1;
            ulong v2 = 0x6c7967656e657261UL ^ key0;
            ulong v3 = 0x7465646279746573UL ^ key1;
            int offset = 0;

            while (offset + 8 <= data.Length)
            {
                ulong word = BinaryPrimitives.ReadUInt64LittleEndian(data[offset..]);
                v3 ^= word;
                SipRound(ref v0, ref v1, ref v2, ref v3);
                SipRound(ref v0, ref v1, ref v2, ref v3);
                v0 ^= word;
                offset += 8;
            }

            ulong tail = (ulong)data.Length << 56;
            for (int i = 0; offset + i < data.Length; i++)
                tail |= (ulong)data[offset + i] << (8 * i);

            v3 ^= tail;
            SipRound(ref v0, ref v1, ref v2, ref v3);
            SipRound(ref v0, ref v1, ref v2, ref v3);
            v0 ^= tail;
            v2 ^= 0xff;
            for (int i = 0; i < 4; i++)
                SipRound(ref v0, ref v1, ref v2, ref v3);

            return v0 ^ v1 ^ v2 ^ v3;
        }

        private static void SipRound(ref ulong v0, ref ulong v1, ref ulong v2, ref ulong v3)
        {
            v0 += v1; v1 = BitOperations.RotateLeft(v1, 13); v1 ^= v0; v0 = BitOperations.RotateLeft(v0, 32);
            v2 += v3; v3 = BitOperations.RotateLeft(v3, 16); v3 ^= v2;
            v0 += v3; v3 = BitOperations.RotateLeft(v3, 21); v3 ^= v0;
            v2 += v1; v1 = BitOperations.RotateLeft(v1, 17); v1 ^= v2; v2 = BitOperations.RotateLeft(v2, 32);
        }
    }
}
