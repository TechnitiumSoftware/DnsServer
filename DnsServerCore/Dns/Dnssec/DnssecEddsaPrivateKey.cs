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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using System;
using System.IO;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns.Dnssec;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Dnssec
{
    class DnssecEddsaPrivateKey : DnssecPrivateKey
    {
        #region variables

        Ed25519PrivateKeyParameters _ed25519PrivateKey;
        Ed448PrivateKeyParameters _ed448PrivateKey;

        #endregion

        #region constructors

        public DnssecEddsaPrivateKey(DnssecPrivateKeyType keyType, Ed25519PrivateKeyParameters ed25519PrivateKey)
            : base(DnssecAlgorithm.ED25519, keyType)
        {
            _ed25519PrivateKey = ed25519PrivateKey;

            InitDnsKey();
        }

        public DnssecEddsaPrivateKey(DnssecPrivateKeyType keyType, Ed448PrivateKeyParameters ed448PrivateKey)
            : base(DnssecAlgorithm.ED448, keyType)
        {
            _ed448PrivateKey = ed448PrivateKey;

            InitDnsKey();
        }

        public DnssecEddsaPrivateKey(DnssecAlgorithm algorithm, BinaryReader bR, int version)
            : base(algorithm, bR, version)
        {
            InitDnsKey();
        }

        #endregion

        #region private

        private void InitDnsKey()
        {
            switch (Algorithm)
            {
                case DnssecAlgorithm.ED25519:
                    InitDnsKey(new DnssecEddsaPublicKey(_ed25519PrivateKey.GeneratePublicKey()));
                    break;

                case DnssecAlgorithm.ED448:
                    InitDnsKey(new DnssecEddsaPublicKey(_ed448PrivateKey.GeneratePublicKey()));
                    break;
            }
        }

        #endregion

        #region protected

        protected override byte[] SignHash(byte[] hash)
        {
            ISigner signer;

            switch (Algorithm)
            {
                case DnssecAlgorithm.ED25519:
                    signer = new Ed25519Signer();
                    signer.Init(true, _ed25519PrivateKey);
                    break;

                case DnssecAlgorithm.ED448:
                    signer = new Ed448Signer([]);
                    signer.Init(true, _ed448PrivateKey);
                    break;

                default:
                    throw new InvalidOperationException();
            }

            signer.BlockUpdate(hash);

            return signer.GenerateSignature();
        }

        protected override void ReadPrivateKeyFrom(BinaryReader bR)
        {
            switch (Algorithm)
            {
                case DnssecAlgorithm.ED25519:
                    _ed25519PrivateKey = new Ed25519PrivateKeyParameters(bR.ReadBuffer());
                    break;

                case DnssecAlgorithm.ED448:
                    _ed448PrivateKey = new Ed448PrivateKeyParameters(bR.ReadBuffer());
                    break;

                default:
                    throw new InvalidDataException();
            }
        }

        protected override void WritePrivateKeyTo(BinaryWriter bW)
        {
            switch (Algorithm)
            {
                case DnssecAlgorithm.ED25519:
                    bW.WriteBuffer(_ed25519PrivateKey.GetEncoded());
                    break;

                case DnssecAlgorithm.ED448:
                    bW.WriteBuffer(_ed448PrivateKey.GetEncoded());
                    break;

                default:
                    throw new InvalidDataException();
            }
        }

        #endregion
    }
}
