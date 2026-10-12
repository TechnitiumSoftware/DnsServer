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

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using System.IO;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns.Dnssec;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Dnssec
{
    class DnssecMldsaPrivateKey : DnssecPrivateKey
    {
        #region variables

        MLDsaPrivateKeyParameters _privateKey;

        #endregion

        #region constructor

        public DnssecMldsaPrivateKey(DnssecPrivateKeyType keyType, MLDsaPrivateKeyParameters privateKey)
            : base(DnssecAlgorithm.MLDSA44, keyType)
        {
            _privateKey = privateKey;

            InitDnsKey();
        }

        public DnssecMldsaPrivateKey(DnssecAlgorithm algorithm, BinaryReader bR, int version)
            : base(algorithm, bR, version)
        {
            InitDnsKey();
        }

        #endregion

        #region private

        private void InitDnsKey()
        {
            InitDnsKey(new DnssecMldsaPublicKey(_privateKey.GetPublicKeyEncoded()));
        }

        #endregion

        #region protected

        protected override byte[] SignHash(byte[] hash)
        {
            //pure ML-DSA-44 signing with an empty context; must match the verifier's signer construction
            MLDsaSigner signer = new MLDsaSigner(MLDsaParameters.ml_dsa_44, false);
            signer.Init(true, _privateKey);
            signer.BlockUpdate(hash, 0, hash.Length);

            return signer.GenerateSignature();
        }

        protected override void ReadPrivateKeyFrom(BinaryReader bR)
        {
            switch (Algorithm)
            {
                case DnssecAlgorithm.MLDSA44:
                    _privateKey = MLDsaPrivateKeyParameters.FromSeed(MLDsaParameters.ml_dsa_44, bR.ReadBuffer());
                    break;

                default:
                    throw new InvalidDataException();
            }
        }

        protected override void WritePrivateKeyTo(BinaryWriter bW)
        {
            bW.WriteBuffer(_privateKey.GetSeed());
        }

        #endregion
    }
}
