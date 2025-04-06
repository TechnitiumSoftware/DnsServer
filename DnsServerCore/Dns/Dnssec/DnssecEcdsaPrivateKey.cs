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
    class DnssecEcdsaPrivateKey : DnssecPrivateKey
    {
        #region variables

        ECParameters _ecdsaPrivateKey;

        #endregion

        #region constructor

        public DnssecEcdsaPrivateKey(DnssecAlgorithm algorithm, DnssecPrivateKeyType keyType, ECParameters ecdsaPrivateKey)
            : base(algorithm, keyType)
        {
            _ecdsaPrivateKey = ecdsaPrivateKey;

            InitDnsKey();
        }

        public DnssecEcdsaPrivateKey(DnssecAlgorithm algorithm, BinaryReader bR, int version)
            : base(algorithm, bR, version)
        {
            InitDnsKey();
        }

        #endregion

        #region private

        private void InitDnsKey()
        {
            ECParameters ecdsaPublicKey = new ECParameters
            {
                Curve = _ecdsaPrivateKey.Curve,
                Q = _ecdsaPrivateKey.Q
            };

            InitDnsKey(new DnssecEcdsaPublicKey(ecdsaPublicKey));
        }

        #endregion

        #region protected

        protected override byte[] SignHash(byte[] hash)
        {
            using (ECDsa ecdsa = ECDsa.Create(_ecdsaPrivateKey))
            {
                return ecdsa.SignHash(hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
        }

        protected override void ReadPrivateKeyFrom(BinaryReader bR)
        {
            switch (Algorithm)
            {
                case DnssecAlgorithm.ECDSAP256SHA256:
                    _ecdsaPrivateKey.Curve = ECCurve.NamedCurves.nistP256;
                    break;

                case DnssecAlgorithm.ECDSAP384SHA384:
                    _ecdsaPrivateKey.Curve = ECCurve.NamedCurves.nistP384;
                    break;

                default:
                    throw new InvalidDataException();
            }

            _ecdsaPrivateKey.D = bR.ReadBuffer();
            _ecdsaPrivateKey.Q.X = bR.ReadBuffer();
            _ecdsaPrivateKey.Q.Y = bR.ReadBuffer();
        }

        protected override void WritePrivateKeyTo(BinaryWriter bW)
        {
            bW.WriteBuffer(_ecdsaPrivateKey.D);
            bW.WriteBuffer(_ecdsaPrivateKey.Q.X);
            bW.WriteBuffer(_ecdsaPrivateKey.Q.Y);
        }

        #endregion
    }
}
