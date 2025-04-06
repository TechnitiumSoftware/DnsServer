/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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

using System.IO;
using System.Security.Cryptography;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns.Dnssec;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Dnssec
{
    class DnssecRsaPrivateKey : DnssecPrivateKey
    {
        #region variables

        int _keySize;
        RSAParameters _rsaPrivateKey;
        readonly HashAlgorithmName _hashAlgorithm;

        #endregion

        #region constructor

        public DnssecRsaPrivateKey(DnssecAlgorithm algorithm, DnssecPrivateKeyType keyType, int keySize, RSAParameters rsaPrivateKey)
            : base(algorithm, keyType)
        {
            _keySize = keySize;
            _rsaPrivateKey = rsaPrivateKey;

            _hashAlgorithm = DnsRRSIGRecordData.GetHashAlgorithmName(algorithm);
            InitDnsKey();
        }

        public DnssecRsaPrivateKey(DnssecAlgorithm algorithm, BinaryReader bR, int version)
            : base(algorithm, bR, version)
        {
            _hashAlgorithm = DnsRRSIGRecordData.GetHashAlgorithmName(algorithm);
            InitDnsKey();
        }

        #endregion

        #region private

        private void InitDnsKey()
        {
            RSAParameters rsaPublicKey = new RSAParameters
            {
                Exponent = _rsaPrivateKey.Exponent,
                Modulus = _rsaPrivateKey.Modulus
            };

            InitDnsKey(new DnssecRsaPublicKey(rsaPublicKey));
        }

        #endregion

        #region protected

        protected override byte[] SignHash(byte[] hash)
        {
            using (RSA rsa = RSA.Create(_rsaPrivateKey))
            {
                return rsa.SignHash(hash, _hashAlgorithm, RSASignaturePadding.Pkcs1);
            }
        }

        protected override void ReadPrivateKeyFrom(BinaryReader bR)
        {
            _keySize = bR.ReadInt32();

            _rsaPrivateKey.D = bR.ReadBuffer();
            _rsaPrivateKey.DP = bR.ReadBuffer();
            _rsaPrivateKey.DQ = bR.ReadBuffer();
            _rsaPrivateKey.Exponent = bR.ReadBuffer();
            _rsaPrivateKey.InverseQ = bR.ReadBuffer();
            _rsaPrivateKey.Modulus = bR.ReadBuffer();
            _rsaPrivateKey.P = bR.ReadBuffer();
            _rsaPrivateKey.Q = bR.ReadBuffer();
        }

        protected override void WritePrivateKeyTo(BinaryWriter bW)
        {
            bW.Write(_keySize);

            bW.WriteBuffer(_rsaPrivateKey.D);
            bW.WriteBuffer(_rsaPrivateKey.DP);
            bW.WriteBuffer(_rsaPrivateKey.DQ);
            bW.WriteBuffer(_rsaPrivateKey.Exponent);
            bW.WriteBuffer(_rsaPrivateKey.InverseQ);
            bW.WriteBuffer(_rsaPrivateKey.Modulus);
            bW.WriteBuffer(_rsaPrivateKey.P);
            bW.WriteBuffer(_rsaPrivateKey.Q);
        }

        #endregion

        #region protected

        public int KeySize
        { get { return _keySize; } }

        #endregion
    }
}
