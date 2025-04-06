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

using DnsServerCore.Dns.Zones;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using TechnitiumLibrary.Net.Dns.Dnssec;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Dnssec
{
    //DNSSEC Key Rollover Timing Considerations
    //https://datatracker.ietf.org/doc/html/rfc7583

    public enum DnssecPrivateKeyType : byte
    {
        Unknown = 0,
        KeySigningKey = 1,
        ZoneSigningKey = 2
    }

    public enum DnssecPrivateKeyState : byte
    {
        Unknown = 0,

        /// <summary>
        /// Although keys may be created immediately prior to first
        /// use, some implementations may find it convenient to
        /// create a pool of keys in one operation and draw from it
        /// as required.  (Note: such a pre-generated pool must be
        /// secured against surreptitious use.)  In the timelines
        /// below, before the first event, the keys are considered to
        /// be created but not yet used: they are said to be in the
        /// "Generated" state.
        /// </summary>
        Generated = 1,

        /// <summary>
        /// A key enters the published state when either it or its associated data 
        /// first appears in the appropriate zone.
        /// </summary>
        Published = 2,

        /// <summary>
        /// The DNSKEY or its associated data have been published for long enough 
        /// to guarantee that copies of the key(s) it is replacing (or associated 
        /// data related to that key) have expired from caches.
        /// </summary>
        Ready = 3,

        /// <summary>
        /// The data is starting to be used for validation.  In the
        /// case of a ZSK, it means that the key is now being used to
        /// sign RRsets and that both it and the created RRSIGs
        /// appear in the zone.  In the case of a KSK, it means that
        /// it is possible to use it to validate a DNSKEY RRset as
        /// both the DNSKEY and DS records are present in their
        /// respective zones.  Note that when this state is entered,
        /// it may not be possible for validating resolvers to use
        /// the data for validation in all cases: the zone signing
        /// may not have finished or the data might not have reached
        /// the resolver because of propagation delays and/or caching
        /// issues.  If this is the case, the resolver will have to
        /// rely on the predecessor data instead.
        /// </summary>
        Active = 4,

        /// <summary>
        /// The data has ceased to be used for validation.  In the
        /// case of a ZSK, it means that the key is no longer used to
        /// sign RRsets.  In the case of a KSK, it means that the
        /// successor DNSKEY and DS records are in place.  In both
        /// cases, the key (and its associated data) can be removed
        /// as soon as it is safe to do so, i.e., when all validating
        /// resolvers are able to use the new key and associated data
        /// to validate the zone.However, until this happens, the
        /// current key and associated data must remain in their
        /// respective zones.
        /// </summary>
        Retired = 5,

        /// <summary>
        /// The key and its associated data are present in their
        /// respective zones, but there is no longer information
        /// anywhere that requires their presence for use in
        /// validation.  Hence, they can be removed at any time.
        /// </summary>
        Dead = 6,

        /// <summary>
        /// Both the DNSKEY and its associated data have been removed
        /// from their respective zones.
        /// </summary>
        Removed = 7,

        /// <summary>
        /// The DNSKEY is published for a period with the "revoke"
        /// bit set as a way of notifying validating resolvers that
        /// have configured it as a trust anchor, as used in
        /// [RFC5011], that it is about to be removed from the zone.
        /// This state is used when [RFC5011] considerations are in
        /// effect (see Section 3.3.4).
        /// </summary>
        Revoked = 8
    }

    public abstract class DnssecPrivateKey
    {
        #region variables

        readonly DnssecAlgorithm _algorithm;
        readonly DnssecPrivateKeyType _keyType;

        DnssecPrivateKeyState _state;
        DateTime _stateChangedOn;
        DateTime _stateTransitionBy;
        bool _isRetiring;
        ushort _rolloverDays;

        DnsDNSKEYRecordData _dnsKey;

        #endregion

        #region constructor

        protected DnssecPrivateKey(DnssecAlgorithm algorithm, DnssecPrivateKeyType keyType)
        {
            _algorithm = algorithm;
            _keyType = keyType;

            _state = DnssecPrivateKeyState.Generated;
            _stateChangedOn = DateTime.UtcNow;
        }

        protected DnssecPrivateKey(DnssecAlgorithm algorithm, BinaryReader bR, int version)
        {
            _algorithm = algorithm;
            _keyType = (DnssecPrivateKeyType)bR.ReadByte();

            _state = (DnssecPrivateKeyState)bR.ReadByte();
            _stateChangedOn = DateTime.UnixEpoch.AddSeconds(bR.ReadInt64());

            if (version >= 2)
                _stateTransitionBy = DateTime.UnixEpoch.AddSeconds(bR.ReadInt64());

            _isRetiring = bR.ReadBoolean();
            _rolloverDays = bR.ReadUInt16();

            ReadPrivateKeyFrom(bR);
        }

        #endregion

        #region static

        public static DnssecPrivateKey Create(DnssecAlgorithm algorithm, DnssecPrivateKeyType keyType, int keySize = -1)
        {
            switch (algorithm)
            {
                case DnssecAlgorithm.RSAMD5:
                case DnssecAlgorithm.RSASHA1:
                case DnssecAlgorithm.RSASHA1_NSEC3_SHA1:
                case DnssecAlgorithm.RSASHA256:
                case DnssecAlgorithm.RSASHA512:
                    if ((keySize < 1024) || (keySize > 4096))
                        throw new ArgumentOutOfRangeException(nameof(keySize), $"Valid RSA ({(keyType == DnssecPrivateKeyType.KeySigningKey ? "KSK" : "ZSK")}) private key size range is between 1024-4096 bits.");

                    using (RSA rsa = RSA.Create(keySize))
                    {
                        return new DnssecRsaPrivateKey(algorithm, keyType, keySize, rsa.ExportParameters(true));
                    }

                case DnssecAlgorithm.ECDSAP256SHA256:
                    using (ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256))
                    {
                        return new DnssecEcdsaPrivateKey(algorithm, keyType, ecdsa.ExportParameters(true));
                    }

                case DnssecAlgorithm.ECDSAP384SHA384:
                    using (ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384))
                    {
                        return new DnssecEcdsaPrivateKey(algorithm, keyType, ecdsa.ExportParameters(true));
                    }

                case DnssecAlgorithm.ED25519:
                    return new DnssecEddsaPrivateKey(keyType, new Ed25519PrivateKeyParameters(RandomNumberGenerator.GetBytes(32)));

                case DnssecAlgorithm.ED448:
                    return new DnssecEddsaPrivateKey(keyType, new Ed448PrivateKeyParameters(RandomNumberGenerator.GetBytes(57)));

                default:
                    throw new NotSupportedException("DNSSEC algorithm is not supported: " + algorithm.ToString());
            }
        }

        public static DnssecPrivateKey Create(DnssecAlgorithm algorithm, DnssecPrivateKeyType keyType, string pemPrivateKey)
        {
            switch (algorithm)
            {
                case DnssecAlgorithm.RSAMD5:
                case DnssecAlgorithm.RSASHA1:
                case DnssecAlgorithm.RSASHA1_NSEC3_SHA1:
                case DnssecAlgorithm.RSASHA256:
                case DnssecAlgorithm.RSASHA512:
                    using (RSA rsa = RSA.Create())
                    {
                        rsa.ImportFromPem(pemPrivateKey);

                        if ((rsa.KeySize < 1024) || (rsa.KeySize > 4096))
                            throw new ArgumentOutOfRangeException(nameof(pemPrivateKey), $"Valid RSA ({(keyType == DnssecPrivateKeyType.KeySigningKey ? "KSK" : "ZSK")}) private key size range is between 1024-4096 bits.");

                        return new DnssecRsaPrivateKey(algorithm, keyType, rsa.KeySize, rsa.ExportParameters(true));
                    }

                case DnssecAlgorithm.ECDSAP256SHA256:
                    using (ECDsa ecdsa = ECDsa.Create())
                    {
                        ecdsa.ImportFromPem(pemPrivateKey);

                        if (ecdsa.KeySize != 256)
                            throw new ArgumentException($"The ECDSA ({(keyType == DnssecPrivateKeyType.KeySigningKey ? "KSK" : "ZSK")}) private key must have key size of 256 bits.", nameof(pemPrivateKey));

                        return new DnssecEcdsaPrivateKey(algorithm, keyType, ecdsa.ExportParameters(true));
                    }

                case DnssecAlgorithm.ECDSAP384SHA384:
                    using (ECDsa ecdsa = ECDsa.Create())
                    {
                        ecdsa.ImportFromPem(pemPrivateKey);

                        if (ecdsa.KeySize != 384)
                            throw new ArgumentException($"The ECDSA ({(keyType == DnssecPrivateKeyType.KeySigningKey ? "KSK" : "ZSK")}) private key must have key size of 384 bits.", nameof(pemPrivateKey));

                        return new DnssecEcdsaPrivateKey(algorithm, keyType, ecdsa.ExportParameters(true));
                    }

                case DnssecAlgorithm.ED25519:
                    using (PemReader pemReader = new PemReader(new StringReader(pemPrivateKey)))
                    {
                        if (pemReader.ReadObject() is not Ed25519PrivateKeyParameters privateKey)
                            throw new ArgumentException($"The EdDSA ({(keyType == DnssecPrivateKeyType.KeySigningKey ? "KSK" : "ZSK")}) private key must be for Ed25519 curve.", nameof(pemPrivateKey));

                        return new DnssecEddsaPrivateKey(keyType, privateKey);
                    }

                case DnssecAlgorithm.ED448:
                    using (PemReader pemReader = new PemReader(new StringReader(pemPrivateKey)))
                    {
                        if (pemReader.ReadObject() is not Ed448PrivateKeyParameters privateKey)
                            throw new ArgumentException($"The EdDSA ({(keyType == DnssecPrivateKeyType.KeySigningKey ? "KSK" : "ZSK")}) private key must be for Ed448 curve.", nameof(pemPrivateKey));

                        return new DnssecEddsaPrivateKey(keyType, privateKey);
                    }

                default:
                    throw new NotSupportedException("DNSSEC algorithm is not supported: " + algorithm.ToString());
            }
        }

        public static DnssecPrivateKey ReadFrom(BinaryReader bR)
        {
            if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "DK")
                throw new InvalidDataException("DNSSEC private key format is invalid.");

            int version = bR.ReadByte();
            switch (version)
            {
                case 1:
                case 2:
                    DnssecAlgorithm algorithm = (DnssecAlgorithm)bR.ReadByte();
                    switch (algorithm)
                    {
                        case DnssecAlgorithm.RSAMD5:
                        case DnssecAlgorithm.RSASHA1:
                        case DnssecAlgorithm.RSASHA1_NSEC3_SHA1:
                        case DnssecAlgorithm.RSASHA256:
                        case DnssecAlgorithm.RSASHA512:
                            return new DnssecRsaPrivateKey(algorithm, bR, version);

                        case DnssecAlgorithm.ECDSAP256SHA256:
                        case DnssecAlgorithm.ECDSAP384SHA384:
                            return new DnssecEcdsaPrivateKey(algorithm, bR, version);

                        case DnssecAlgorithm.ED25519:
                        case DnssecAlgorithm.ED448:
                            return new DnssecEddsaPrivateKey(algorithm, bR, version);

                        default:
                            throw new NotSupportedException("DNSSEC algorithm is not supported: " + algorithm.ToString());
                    }

                default:
                    throw new InvalidDataException("DNSSEC private key version not supported: " + version);
            }
        }

        #endregion

        #region protected

        protected void InitDnsKey(DnssecPublicKey publicKey)
        {
            DnsDnsKeyFlag flags = DnsDnsKeyFlag.ZoneKey;

            if (KeyType == DnssecPrivateKeyType.KeySigningKey)
                flags |= DnsDnsKeyFlag.SecureEntryPoint;

            if (_state == DnssecPrivateKeyState.Revoked)
                flags |= DnsDnsKeyFlag.Revoke;

            _dnsKey = new DnsDNSKEYRecordData(flags, 3, _algorithm, publicKey);
        }

        protected abstract byte[] SignHash(byte[] hash);

        protected abstract void ReadPrivateKeyFrom(BinaryReader bR);

        protected abstract void WritePrivateKeyTo(BinaryWriter bW);

        #endregion

        #region internal

        internal DnsResourceRecord SignRRSet(string signersName, IReadOnlyList<DnsResourceRecord> records, uint signatureInceptionOffset, uint signatureValidityPeriod)
        {
            DnsResourceRecord firstRecord = records[0];
            DnsRRSIGRecordData unsignedRRSigRecord = new DnsRRSIGRecordData(firstRecord.Type, _algorithm, DnsRRSIGRecordData.GetLabelCount(firstRecord.Name), firstRecord.OriginalTtlValue, Convert.ToUInt32((DateTime.UtcNow.AddSeconds(signatureValidityPeriod) - DateTime.UnixEpoch).TotalSeconds % uint.MaxValue), Convert.ToUInt32((DateTime.UtcNow.AddSeconds(-signatureInceptionOffset) - DateTime.UnixEpoch).TotalSeconds % uint.MaxValue), DnsKey.ComputedKeyTag, signersName, null);

            if (!DnsRRSIGRecordData.TryGetRRSetHash(unsignedRRSigRecord, records, out byte[] hash, out EDnsExtendedDnsErrorCode extendedDnsErrorCode))
                throw new DnsServerException("Failed to sign record set: " + extendedDnsErrorCode.ToString());

            byte[] signature = SignHash(hash);

            DnsRRSIGRecordData signedRRSigRecord = new DnsRRSIGRecordData(unsignedRRSigRecord.TypeCovered, unsignedRRSigRecord.Algorithm, unsignedRRSigRecord.Labels, unsignedRRSigRecord.OriginalTtl, unsignedRRSigRecord.SignatureExpiration, unsignedRRSigRecord.SignatureInception, unsignedRRSigRecord.KeyTag, unsignedRRSigRecord.SignersName, signature);
            return new DnsResourceRecord(firstRecord.Name, DnsResourceRecordType.RRSIG, firstRecord.Class, firstRecord.OriginalTtlValue, signedRRSigRecord);
        }

        internal void SetState(DnssecPrivateKeyState state, uint stateTransitionInTtl = 0)
        {
            if (_state >= state)
                return; //ignore; state cannot be updated to lower value

            _state = state;
            _stateChangedOn = DateTime.UtcNow;

            if (stateTransitionInTtl > 0)
                _stateTransitionBy = _stateChangedOn.AddSeconds(stateTransitionInTtl);
            else
                _stateTransitionBy = default;

            if (_state == DnssecPrivateKeyState.Revoked)
                InitDnsKey(_dnsKey.PublicKey);
        }

        internal void SetToRetire()
        {
            _isRetiring = true;
        }

        internal bool IsRolloverNeeded()
        {
            return (_rolloverDays > 0) && (DateTime.UtcNow > _stateChangedOn.AddDays(_rolloverDays));
        }

        internal void WriteTo(BinaryWriter bW)
        {
            bW.Write(Encoding.ASCII.GetBytes("DK")); //format
            bW.Write((byte)2); //version

            bW.Write((byte)_algorithm);
            bW.Write((byte)_keyType);

            bW.Write((byte)_state);
            bW.Write(Convert.ToInt64((_stateChangedOn - DateTime.UnixEpoch).TotalSeconds));
            bW.Write(Convert.ToInt64((_stateTransitionBy - DateTime.UnixEpoch).TotalSeconds));
            bW.Write(_isRetiring);
            bW.Write(_rolloverDays);

            WritePrivateKeyTo(bW);
        }

        #endregion

        #region properties

        public DnssecAlgorithm Algorithm
        { get { return _algorithm; } }

        public DnssecPrivateKeyType KeyType
        { get { return _keyType; } }

        public DnssecPrivateKeyState State
        { get { return _state; } }

        public DateTime StateChangedOn
        { get { return _stateChangedOn; } }

        public DateTime StateTransitionBy
        { get { return _stateTransitionBy; } }

        public DateTime StateTransitionByWithDelays
        { get { return _stateTransitionBy.AddMilliseconds(PrimaryZone.DNSSEC_TIMER_PERIODIC_INTERVAL); } }

        public bool IsRetiring
        { get { return _isRetiring; } }

        public ushort RolloverDays
        {
            get { return _rolloverDays; }
            set
            {
                if (_keyType == DnssecPrivateKeyType.ZoneSigningKey)
                {
                    if (value > 365)
                        throw new ArgumentOutOfRangeException(nameof(RolloverDays), "Zone Signing Key (ZSK) automatic rollover days valid range is 0-365.");

                    switch (_state)
                    {
                        case DnssecPrivateKeyState.Generated:
                        case DnssecPrivateKeyState.Published:
                        case DnssecPrivateKeyState.Ready:
                        case DnssecPrivateKeyState.Active:
                            if (_isRetiring)
                                throw new InvalidOperationException("Zone Signing Key (ZSK) automatic rollover cannot be set since it is set to retire.");

                            break;

                        default:
                            throw new InvalidOperationException("Zone Signing Key (ZSK) automatic rollover cannot be set due to invalid key state.");
                    }
                }
                else
                {
                    if (value != 0)
                        throw new NotSupportedException("Automatic rollover is not supported for Key Signing Keys (KSK).");
                }

                _rolloverDays = value;
            }
        }

        public DnsDNSKEYRecordData DnsKey
        { get { return _dnsKey; } }

        public ushort KeyTag
        { get { return _dnsKey.ComputedKeyTag; } }

        #endregion
    }
}
