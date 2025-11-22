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

using DnsServerCore.Dns.Dnssec;
using DnsServerCore.Dns.ResourceRecords;
using DnsServerCore.Dns.ZoneManagers;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    public enum AuthZoneDnssecStatus : byte
    {
        Unsigned = 0,
        SignedWithNSEC = 1,
        SignedWithNSEC3 = 2,
    }

    //DNSSEC Operational Practices, Version 2
    //https://datatracker.ietf.org/doc/html/rfc6781

    //DNSSEC Key Rollover Timing Considerations
    //https://datatracker.ietf.org/doc/html/rfc7583

    class PrimaryZone : ApexZone
    {
        #region variables

        readonly bool _internal;

        Dictionary<ushort, DnssecPrivateKey> _dnssecPrivateKeys;
        const uint DNSSEC_SIGNATURE_INCEPTION_OFFSET = 60 * 60;

        Timer _dnssecTimer;
        const int DNSSEC_TIMER_INITIAL_INTERVAL = 30000;
        internal const int DNSSEC_TIMER_PERIODIC_INTERVAL = 900000;

        DateTime _lastSignatureRefreshCheckedOn;
        readonly object _dnssecUpdateLock = new object();

        #endregion

        #region constructor

        public PrimaryZone(DnsServer dnsServer, AuthZoneInfo zoneInfo)
            : base(dnsServer, zoneInfo)
        {
            IReadOnlyCollection<DnssecPrivateKey> dnssecPrivateKeys = zoneInfo.DnssecPrivateKeys;
            if (dnssecPrivateKeys is not null)
            {
                _dnssecPrivateKeys = new Dictionary<ushort, DnssecPrivateKey>(dnssecPrivateKeys.Count);

                foreach (DnssecPrivateKey dnssecPrivateKey in dnssecPrivateKeys)
                    _dnssecPrivateKeys.Add(dnssecPrivateKey.KeyTag, dnssecPrivateKey);
            }

            InitNotify();
            InitRecordExpiry();
        }

        public PrimaryZone(DnsServer dnsServer, string name, bool @internal, bool useSoaSerialDateScheme)
            : base(dnsServer, name)
        {
            _internal = @internal;

            if (!_internal)
            {
                InitNotify();
                InitRecordExpiry();

                ZoneTransfer = AuthZoneTransfer.AllowOnlyZoneNameServers;
                Notify = AuthZoneNotify.ZoneNameServers;
            }

            string rp;

            if (_dnsServer.ResponsiblePersonInternal is null)
                rp = _name.Length == 0 ? _dnsServer.ResponsiblePerson.Address : "hostadmin@" + _name;
            else
                rp = _dnsServer.ResponsiblePersonInternal.Address;

            uint serial = GetNewSerial(0, 0, useSoaSerialDateScheme);
            DnsSOARecordData soa = new DnsSOARecordData(_dnsServer.ServerDomain, rp, serial, 900, 300, 604800, 900);
            DnsResourceRecord soaRecord = new DnsResourceRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN, soa.Minimum, soa);
            soaRecord.GetAuthSOARecordInfo().UseSoaSerialDateScheme = useSoaSerialDateScheme;
            soaRecord.GetAuthSOARecordInfo().LastModified = DateTime.UtcNow;

            DnsResourceRecord nsRecord = new DnsResourceRecord(_name, DnsResourceRecordType.NS, DnsClass.IN, 3600, new DnsNSRecordData(soa.PrimaryNameServer));
            nsRecord.GetAuthNSRecordInfo().LastModified = DateTime.UtcNow;

            _entries[DnsResourceRecordType.SOA] = [soaRecord];
            _entries[DnsResourceRecordType.NS] = [nsRecord];
        }

        internal PrimaryZone(DnsServer dnsServer, string name, DnsSOARecordData soa, DnsNSRecordData ns)
            : base(dnsServer, name)
        {
            _internal = true;

            _entries[DnsResourceRecordType.SOA] = [new DnsResourceRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN, soa.Minimum, soa)];
            _entries[DnsResourceRecordType.NS] = [new DnsResourceRecord(_name, DnsResourceRecordType.NS, DnsClass.IN, 3600, ns)];
        }

        #endregion

        #region IDisposable

        bool _disposed;

        protected override void Dispose(bool disposing)
        {
            try
            {
                if (_disposed)
                    return;

                if (disposing)
                {
                    Timer dnssecTimer = _dnssecTimer;
                    if (dnssecTimer is not null)
                    {
                        lock (dnssecTimer)
                        {
                            dnssecTimer.Dispose();
                            _dnssecTimer = null;
                        }
                    }
                }

                _disposed = true;
            }
            finally
            {
                base.Dispose(disposing);
            }
        }

        #endregion

        #region DNSSEC

        internal override void UpdateDnssecStatus()
        {
            base.UpdateDnssecStatus();

            if (_dnssecStatus != AuthZoneDnssecStatus.Unsigned)
            {
                if (_dnssecPrivateKeys is not null)
                    _dnssecTimer = new Timer(DnssecTimerCallback, null, DNSSEC_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        private async void DnssecTimerCallback(object state)
        {
            try
            {
                List<DnssecPrivateKey> kskToReady = null;
                List<DnssecPrivateKey> kskToActivate = null;
                List<DnssecPrivateKey> kskToRetire = null;
                List<DnssecPrivateKey> kskToRevoke = null;

                List<DnssecPrivateKey> zskToActivate = null;
                List<DnssecPrivateKey> zskToRetire = null;
                List<DnssecPrivateKey> zskToRollover = null;

                List<DnssecPrivateKey> keysToUnpublish = null;

                bool saveZone = false;

                lock (_dnssecPrivateKeys)
                {
                    foreach (KeyValuePair<ushort, DnssecPrivateKey> privateKeyEntry in _dnssecPrivateKeys)
                    {
                        DnssecPrivateKey privateKey = privateKeyEntry.Value;

                        if (privateKey.KeyType == DnssecPrivateKeyType.KeySigningKey)
                        {
                            //KSK
                            switch (privateKey.State)
                            {
                                case DnssecPrivateKeyState.Published:
                                    if (DateTime.UtcNow > privateKey.StateTransitionBy)
                                    {
                                        //long enough time for old RRsets to expire from caches
                                        if (kskToReady is null)
                                            kskToReady = new List<DnssecPrivateKey>();

                                        kskToReady.Add(privateKey);
                                    }
                                    break;

                                case DnssecPrivateKeyState.Ready:
                                    if (privateKey.IsRetiring)
                                    {
                                        if (kskToRetire is null)
                                            kskToRetire = new List<DnssecPrivateKey>();

                                        kskToRetire.Add(privateKey);
                                    }
                                    else
                                    {
                                        if (kskToActivate is null)
                                            kskToActivate = new List<DnssecPrivateKey>();

                                        kskToActivate.Add(privateKey);
                                    }
                                    break;

                                case DnssecPrivateKeyState.Active:
                                    if (privateKey.IsRetiring)
                                    {
                                        if (kskToRetire is null)
                                            kskToRetire = new List<DnssecPrivateKey>();

                                        kskToRetire.Add(privateKey);
                                    }
                                    break;

                                case DnssecPrivateKeyState.Retired:
                                    //KSK needs to be revoked for RFC5011 consideration
                                    if (DateTime.UtcNow > privateKey.StateTransitionBy)
                                    {
                                        //key has been retired for sufficient time
                                        if (kskToRevoke is null)
                                            kskToRevoke = new List<DnssecPrivateKey>();

                                        kskToRevoke.Add(privateKey);
                                    }
                                    break;

                                case DnssecPrivateKeyState.Revoked:
                                    if (DateTime.UtcNow > privateKey.StateTransitionBy)
                                    {
                                        //key has been revoked for sufficient time
                                        if (keysToUnpublish is null)
                                            keysToUnpublish = new List<DnssecPrivateKey>();

                                        keysToUnpublish.Add(privateKey);
                                    }
                                    break;
                            }
                        }
                        else
                        {
                            //ZSK
                            switch (privateKey.State)
                            {
                                case DnssecPrivateKeyState.Published:
                                    if (DateTime.UtcNow > privateKey.StateTransitionBy)
                                    {
                                        //long enough time old RRset to expire from caches
                                        privateKey.SetState(DnssecPrivateKeyState.Ready);

                                        if (zskToActivate is null)
                                            zskToActivate = new List<DnssecPrivateKey>();

                                        zskToActivate.Add(privateKey);
                                    }
                                    break;

                                case DnssecPrivateKeyState.Ready:
                                    if (zskToActivate is null)
                                        zskToActivate = new List<DnssecPrivateKey>();

                                    zskToActivate.Add(privateKey);
                                    break;

                                case DnssecPrivateKeyState.Active:
                                    if (privateKey.IsRetiring)
                                    {
                                        if (zskToRetire is null)
                                            zskToRetire = new List<DnssecPrivateKey>();

                                        zskToRetire.Add(privateKey);
                                    }
                                    else
                                    {
                                        if (privateKey.IsRolloverNeeded())
                                        {
                                            if (zskToRollover is null)
                                                zskToRollover = new List<DnssecPrivateKey>();

                                            zskToRollover.Add(privateKey);
                                        }
                                    }
                                    break;

                                case DnssecPrivateKeyState.Retired:
                                    if (DateTime.UtcNow > privateKey.StateTransitionBy)
                                    {
                                        //key has been retired for sufficient time
                                        if (keysToUnpublish is null)
                                            keysToUnpublish = new List<DnssecPrivateKey>();

                                        keysToUnpublish.Add(privateKey);
                                    }
                                    break;
                            }
                        }
                    }
                }

                #region KSK actions

                if (kskToReady is not null)
                {
                    string dnsKeyTags = null;

                    foreach (DnssecPrivateKey kskPrivateKey in kskToReady)
                    {
                        kskPrivateKey.SetState(DnssecPrivateKeyState.Ready);

                        if (kskToActivate is null)
                            kskToActivate = new List<DnssecPrivateKey>();

                        kskToActivate.Add(kskPrivateKey);

                        if (dnsKeyTags is null)
                            dnsKeyTags = kskPrivateKey.KeyTag.ToString();
                        else
                            dnsKeyTags += ", " + kskPrivateKey.KeyTag.ToString();
                    }

                    saveZone = true;

                    _dnsServer.LogManager.Write("The KSK DNSKEYs (" + dnsKeyTags + ") from the primary zone are ready for changing the DS records at the parent zone: " + ToString());
                }

                if (kskToActivate is not null)
                {
                    try
                    {
                        IReadOnlyList<DnssecPrivateKey> kskPrivateKeys = await GetDSPublishedPrivateKeysAsync(kskToActivate);
                        if (kskPrivateKeys.Count > 0)
                        {
                            string dnsKeyTags = null;

                            foreach (DnssecPrivateKey kskPrivateKey in kskPrivateKeys)
                            {
                                kskPrivateKey.SetState(DnssecPrivateKeyState.Active);

                                if (dnsKeyTags is null)
                                    dnsKeyTags = kskPrivateKey.KeyTag.ToString();
                                else
                                    dnsKeyTags += ", " + kskPrivateKey.KeyTag.ToString();
                            }

                            saveZone = true;

                            _dnsServer.LogManager.Write("The KSK DNSKEYs (" + dnsKeyTags + ") from the primary zone were activated successfully: " + ToString());
                        }
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write(ex);
                    }
                }

                if (kskToRetire is not null)
                {
                    if (await RetireKskDnsKeysAsync(kskToRetire, false))
                        saveZone = true;
                }

                if (kskToRevoke is not null)
                {
                    RevokeKskDnsKeys(kskToRevoke);
                    saveZone = true;
                }

                #endregion

                #region ZSK actions

                if (zskToActivate is not null)
                {
                    ActivateZskDnsKeys(zskToActivate);
                    saveZone = true;
                }

                if (zskToRetire is not null)
                {
                    if (RetireZskDnsKeys(zskToRetire, false))
                        saveZone = true;
                }

                if (zskToRollover is not null)
                {
                    foreach (DnssecPrivateKey zskPrivateKey in zskToRollover)
                        RolloverDnsKey(zskPrivateKey.KeyTag);

                    saveZone = true;
                }

                #endregion

                if (keysToUnpublish is not null)
                {
                    UnpublishDnsKeys(keysToUnpublish);
                    saveZone = true;
                }

                //re-signing task
                uint reSignPeriod = GetSignatureValidityPeriod() / 10; //the period when signature refresh check is done
                if (DateTime.UtcNow > _lastSignatureRefreshCheckedOn.AddSeconds(reSignPeriod))
                {
                    if (TryRefreshAllSignatures())
                        saveZone = true;

                    _lastSignatureRefreshCheckedOn = DateTime.UtcNow;
                }

                if (saveZone)
                    _dnsServer.AuthZoneManager.SaveZoneFile(_name);
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write(ex);
            }
            finally
            {
                Timer dnssecTimer = _dnssecTimer;
                if (dnssecTimer is not null)
                {
                    lock (dnssecTimer)
                    {
                        dnssecTimer.Change(DNSSEC_TIMER_PERIODIC_INTERVAL, Timeout.Infinite);
                    }
                }
            }
        }

        public void SignZone(DnssecPrivateKey kskPrivateKey, DnssecPrivateKey zskPrivateKey, uint dnsKeyTtl, bool useNSec3, ushort iterations = 0, byte saltLength = 0)
        {
            if (kskPrivateKey.KeyType != DnssecPrivateKeyType.KeySigningKey)
                throw new ArgumentException("The private key must be a Key Signing Key.", nameof(kskPrivateKey));

            if (zskPrivateKey.KeyType != DnssecPrivateKeyType.ZoneSigningKey)
                throw new ArgumentException("The private key must be a Zone Signing Key.", nameof(zskPrivateKey));

            byte[] salt = null;

            if (useNSec3)
            {
                if (saltLength > 32)
                    throw new ArgumentOutOfRangeException(nameof(saltLength), "NSEC3 salt length valid range is 0-32");

                if (saltLength > 0)
                {
                    salt = new byte[saltLength];
                    RandomNumberGenerator.Fill(salt);
                }
                else
                {
                    salt = [];
                }
            }

            SignZone([kskPrivateKey, zskPrivateKey], dnsKeyTtl, useNSec3, iterations, salt);
        }

        public void SignZone(IReadOnlyCollection<DnssecPrivateKey> dnssecPrivateKeys, uint dnsKeyTtl, bool useNSec3, ushort iterations = 0, byte[] salt = null)
        {
            //do validations
            if (_dnssecStatus != AuthZoneDnssecStatus.Unsigned)
                throw new DnsServerException("Cannot sign zone: the zone is already signed.");

            if (useNSec3)
            {
                if (iterations > 50)
                    throw new ArgumentOutOfRangeException(nameof(iterations), "NSEC3 iterations valid range is 0-50");

                if (salt.Length > 32)
                    throw new ArgumentOutOfRangeException(nameof(salt), "NSEC3 salt length valid range is 0-32");
            }

            bool foundKsk = false;
            bool foundZsk = false;

            foreach (DnssecPrivateKey dnssecPrivateKey in dnssecPrivateKeys)
            {
                switch (dnssecPrivateKey.KeyType)
                {
                    case DnssecPrivateKeyType.KeySigningKey:
                        foundKsk = true;
                        break;

                    case DnssecPrivateKeyType.ZoneSigningKey:
                        foundZsk = true;
                        break;
                }
            }

            if (!foundKsk)
                throw new ArgumentException("The private keys must contain at least one Key Signing Key.", nameof(dnssecPrivateKeys));

            if (!foundZsk)
                throw new ArgumentException("The private keys must contain at least one Zone Signing Key.", nameof(dnssecPrivateKeys));

            //load dnssec private keys
            _dnssecPrivateKeys = new Dictionary<ushort, DnssecPrivateKey>(dnssecPrivateKeys.Count);

            foreach (DnssecPrivateKey dnssecPrivateKey in dnssecPrivateKeys)
                _dnssecPrivateKeys.Add(dnssecPrivateKey.KeyTag, dnssecPrivateKey);

            //start zone signing
            List<DnsResourceRecord> addedRecords = new List<DnsResourceRecord>();
            List<DnsResourceRecord> deletedRecords = new List<DnsResourceRecord>();

            try
            {
                IReadOnlyList<AuthZone> zones = _dnsServer.AuthZoneManager.GetApexZoneWithSubDomainZones(_name);

                //find max record ttl in zone
                uint maxRecordTtl = 0;

                foreach (AuthZone zone in zones)
                {
                    foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in zone.Entries)
                    {
                        IReadOnlyList<DnsResourceRecord> rrset = entry.Value;

                        //find min TTL
                        uint rrsetTtl = 0;

                        foreach (DnsResourceRecord rr in rrset)
                        {
                            if ((rrsetTtl == 0) || (rrsetTtl > rr.OriginalTtlValue))
                                rrsetTtl = rr.OriginalTtlValue;
                        }

                        if (rrsetTtl > maxRecordTtl)
                            maxRecordTtl = rrsetTtl;
                    }
                }

                //update private key state                
                uint propagationDelay = GetPropagationDelay();

                foreach (KeyValuePair<ushort, DnssecPrivateKey> privateKeyEntry in _dnssecPrivateKeys)
                {
                    DnssecPrivateKey privateKey = privateKeyEntry.Value;
                    if (privateKey.State == DnssecPrivateKeyState.Generated)
                    {
                        switch (privateKey.KeyType)
                        {
                            case DnssecPrivateKeyType.KeySigningKey:
                                privateKey.SetState(DnssecPrivateKeyState.Published, maxRecordTtl + propagationDelay);
                                break;

                            case DnssecPrivateKeyType.ZoneSigningKey:
                                privateKey.SetState(DnssecPrivateKeyState.Ready);
                                break;
                        }
                    }
                }

                //add DNSKEYs
                List<DnsResourceRecord> dnsKeyRecords = new List<DnsResourceRecord>(_dnssecPrivateKeys.Count);

                foreach (KeyValuePair<ushort, DnssecPrivateKey> privateKey in _dnssecPrivateKeys)
                    dnsKeyRecords.Add(new DnsResourceRecord(_name, DnsResourceRecordType.DNSKEY, DnsClass.IN, dnsKeyTtl, privateKey.Value.DnsKey));

                if (!TrySetRecords(DnsResourceRecordType.DNSKEY, dnsKeyRecords, out IReadOnlyList<DnsResourceRecord> deletedDnsKeyRecords))
                    throw new InvalidOperationException("Failed to add DNSKEY.");

                addedRecords.AddRange(dnsKeyRecords);
                deletedRecords.AddRange(deletedDnsKeyRecords);

                //sign all RRSets
                foreach (AuthZone zone in zones)
                {
                    IReadOnlyList<DnsResourceRecord> newRRSigRecords = zone.SignAllRRSets();
                    if (newRRSigRecords.Count > 0)
                    {
                        zone.AddOrUpdateRRSigRecords(newRRSigRecords, out IReadOnlyList<DnsResourceRecord> deletedRRSigRecords);

                        addedRecords.AddRange(newRRSigRecords);
                        deletedRecords.AddRange(deletedRRSigRecords);
                    }
                }

                if (useNSec3)
                {
                    EnableNSec3(zones, iterations, salt);
                    _dnssecStatus = AuthZoneDnssecStatus.SignedWithNSEC3;
                }
                else
                {
                    EnableNSec(zones);
                    _dnssecStatus = AuthZoneDnssecStatus.SignedWithNSEC;
                }

                //update private key state
                foreach (KeyValuePair<ushort, DnssecPrivateKey> privateKeyEntry in _dnssecPrivateKeys)
                {
                    DnssecPrivateKey privateKey = privateKeyEntry.Value;
                    switch (privateKey.KeyType)
                    {
                        case DnssecPrivateKeyType.ZoneSigningKey:
                            if (privateKey.State == DnssecPrivateKeyState.Ready)
                                privateKey.SetState(DnssecPrivateKeyState.Active);

                            break;
                    }
                }

                _dnssecTimer = new Timer(DnssecTimerCallback, null, DNSSEC_TIMER_INITIAL_INTERVAL, Timeout.Infinite);

                CommitAndIncrementSerial(deletedRecords, addedRecords);
                TriggerNotify();
            }
            catch
            {
                _dnssecStatus = AuthZoneDnssecStatus.Unsigned;
                _dnssecPrivateKeys = null;

                Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> addedRecordGroups = DnsResourceRecord.GroupRecords(addedRecords);

                foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> addedRecordGroup in addedRecordGroups)
                {
                    AuthZone zone = _dnsServer.AuthZoneManager.GetAuthZone(_name, addedRecordGroup.Key);

                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> addedRecordEntry in addedRecordGroup.Value)
                        zone.TryDeleteRecords(addedRecordEntry.Key, addedRecordEntry.Value, out _);
                }

                Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> deletedRecordGroups = DnsResourceRecord.GroupRecords(deletedRecords);

                foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> deletedRecordGroup in deletedRecordGroups)
                {
                    AuthZone zone = _dnsServer.AuthZoneManager.GetAuthZone(_name, deletedRecordGroup.Key);

                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> deletedRecordEntry in deletedRecordGroup.Value)
                    {
                        foreach (DnsResourceRecord deletedRecord in deletedRecordEntry.Value)
                            zone.AddRecord(deletedRecord, out _, out _);
                    }
                }

                throw;
            }
        }

        public void UnsignZone()
        {
            if (_dnssecStatus == AuthZoneDnssecStatus.Unsigned)
                throw new DnsServerException("Cannot unsign zone: the is zone not signed.");

            List<DnsResourceRecord> deletedRecords = new List<DnsResourceRecord>();
            IReadOnlyList<AuthZone> zones = _dnsServer.AuthZoneManager.GetApexZoneWithSubDomainZones(_name);

            foreach (AuthZone zone in zones)
            {
                deletedRecords.AddRange(zone.RemoveAllDnssecRecords());

                if (zone is SubDomainZone subDomainZone)
                {
                    if (zone.IsEmpty)
                        _dnsServer.AuthZoneManager.RemoveSubDomainZone(zone.Name); //remove empty sub zone
                    else
                        subDomainZone.AutoUpdateState();
                }
            }

            Timer dnssecTimer = _dnssecTimer;
            if (dnssecTimer is not null)
            {
                lock (dnssecTimer)
                {
                    dnssecTimer.Dispose();
                    _dnssecTimer = null;
                }
            }

            _dnssecPrivateKeys = null;
            _dnssecStatus = AuthZoneDnssecStatus.Unsigned;

            CommitAndIncrementSerial(deletedRecords);
            TriggerNotify();
        }

        public void ConvertToNSec()
        {
            if (_dnssecStatus != AuthZoneDnssecStatus.SignedWithNSEC3)
                throw new DnsServerException("Cannot convert to NSEC: the zone must be signed with NSEC3 for conversion.");

            lock (_dnssecUpdateLock)
            {
                IReadOnlyList<AuthZone> zones = _dnsServer.AuthZoneManager.GetApexZoneWithSubDomainZones(_name);

                DisableNSec3(zones);

                //since zones were removed when disabling NSEC3; get updated non empty zones list
                List<AuthZone> nonEmptyZones = new List<AuthZone>(zones.Count);

                foreach (AuthZone zone in zones)
                {
                    if (!zone.IsEmpty)
                        nonEmptyZones.Add(zone);
                }

                EnableNSec(nonEmptyZones);

                _dnssecStatus = AuthZoneDnssecStatus.SignedWithNSEC;
            }

            TriggerNotify();
        }

        public void ConvertToNSec3(ushort iterations, byte saltLength)
        {
            if (_dnssecStatus != AuthZoneDnssecStatus.SignedWithNSEC)
                throw new DnsServerException("Cannot convert to NSEC3: the zone must be signed with NSEC for conversion.");

            if (iterations > 50)
                throw new ArgumentOutOfRangeException(nameof(iterations), "NSEC3 iterations valid range is 0-50");

            if (saltLength > 32)
                throw new ArgumentOutOfRangeException(nameof(saltLength), "NSEC3 salt length valid range is 0-32");

            lock (_dnssecUpdateLock)
            {
                IReadOnlyList<AuthZone> zones = _dnsServer.AuthZoneManager.GetApexZoneWithSubDomainZones(_name);

                DisableNSec(zones);
                EnableNSec3(zones, iterations, saltLength);

                _dnssecStatus = AuthZoneDnssecStatus.SignedWithNSEC3;
            }

            TriggerNotify();
        }

        public void UpdateNSec3Parameters(ushort iterations, byte saltLength)
        {
            if (_dnssecStatus != AuthZoneDnssecStatus.SignedWithNSEC3)
                throw new DnsServerException("Cannot update NSEC3 parameters: the zone must be signed with NSEC3 first.");

            if (iterations > 50)
                throw new ArgumentOutOfRangeException(nameof(iterations), "NSEC3 iterations valid range is 0-50");

            if (saltLength > 32)
                throw new ArgumentOutOfRangeException(nameof(saltLength), "NSEC3 salt length valid range is 0-32");

            lock (_dnssecUpdateLock)
            {
                IReadOnlyList<AuthZone> zones = _dnsServer.AuthZoneManager.GetApexZoneWithSubDomainZones(_name);

                DisableNSec3(zones);

                //since zones were removed when disabling NSEC3; get updated non empty zones list
                List<AuthZone> nonEmptyZones = new List<AuthZone>(zones.Count);

                foreach (AuthZone zone in zones)
                {
                    if (!zone.IsEmpty)
                        nonEmptyZones.Add(zone);
                }

                EnableNSec3(nonEmptyZones, iterations, saltLength);
            }

            TriggerNotify();
        }

        private void RefreshNSec()
        {
            lock (_dnssecUpdateLock)
            {
                IReadOnlyList<AuthZone> zones = _dnsServer.AuthZoneManager.GetApexZoneWithSubDomainZones(_name);

                EnableNSec(zones);
            }
        }

        private void RefreshNSec3()
        {
            lock (_dnssecUpdateLock)
            {
                IReadOnlyList<AuthZone> zones = _dnsServer.AuthZoneManager.GetApexZoneWithSubDomainZones(_name);

                //get non NSEC3 zones
                List<AuthZone> nonNSec3Zones = new List<AuthZone>(zones.Count);

                foreach (AuthZone zone in zones)
                {
                    if (zone.HasOnlyNSec3Records())
                        continue;

                    nonNSec3Zones.Add(zone);
                }

                IReadOnlyList<DnsResourceRecord> nsec3ParamRecords = GetRecords(DnsResourceRecordType.NSEC3PARAM);
                DnsNSEC3PARAMRecordData nsec3Param = nsec3ParamRecords[0].RDATA as DnsNSEC3PARAMRecordData;

                EnableNSec3(nonNSec3Zones, nsec3Param.Iterations, nsec3Param.Salt);
            }
        }

        private void EnableNSec(IReadOnlyList<AuthZone> zones)
        {
            List<DnsResourceRecord> addedRecords = new List<DnsResourceRecord>();
            List<DnsResourceRecord> deletedRecords = new List<DnsResourceRecord>();

            uint ttl = GetZoneSoaMinimum();

            for (int i = 0; i < zones.Count; i++)
            {
                AuthZone zone = zones[i];
                AuthZone nextZone;

                if (i < zones.Count - 1)
                    nextZone = zones[i + 1];
                else
                    nextZone = zones[0];

                IReadOnlyList<DnsResourceRecord> newNSecRecords = zone.GetUpdatedNSecRRSet(nextZone.Name, ttl);
                if (newNSecRecords.Count > 0)
                {
                    if (!zone.TrySetRecords(DnsResourceRecordType.NSEC, newNSecRecords, out IReadOnlyList<DnsResourceRecord> deletedNSecRecords))
                        throw new DnsServerException("Failed to set DNSSEC records. Please try again.");

                    addedRecords.AddRange(newNSecRecords);
                    deletedRecords.AddRange(deletedNSecRecords);

                    IReadOnlyList<DnsResourceRecord> newRRSigRecords = SignRRSet(newNSecRecords);
                    if (newRRSigRecords.Count > 0)
                    {
                        zone.AddOrUpdateRRSigRecords(newRRSigRecords, out IReadOnlyList<DnsResourceRecord> deletedRRSigRecords);

                        addedRecords.AddRange(newRRSigRecords);
                        deletedRecords.AddRange(deletedRRSigRecords);
                    }
                }
            }

            CommitAndIncrementSerial(deletedRecords, addedRecords);
        }

        private void DisableNSec(IReadOnlyList<AuthZone> zones)
        {
            List<DnsResourceRecord> deletedRecords = new List<DnsResourceRecord>();

            foreach (AuthZone zone in zones)
                deletedRecords.AddRange(zone.RemoveNSecRecordsWithRRSig());

            CommitAndIncrementSerial(deletedRecords);
        }

        private void EnableNSec3(IReadOnlyList<AuthZone> zones, ushort iterations, byte saltLength)
        {
            byte[] salt;

            if (saltLength > 0)
            {
                salt = new byte[saltLength];
                RandomNumberGenerator.Fill(salt);
            }
            else
            {
                salt = [];
            }

            EnableNSec3(zones, iterations, salt);
        }

        private void EnableNSec3(IReadOnlyList<AuthZone> zones, ushort iterations, byte[] salt)
        {
            List<DnsResourceRecord> addedRecords = new List<DnsResourceRecord>();
            List<DnsResourceRecord> deletedRecords = new List<DnsResourceRecord>();

            List<DnsResourceRecord> partialNSec3Records = new List<DnsResourceRecord>(zones.Count);
            int apexLabelCount = DnsRRSIGRecordData.GetLabelCount(_name);

            uint ttl = GetZoneSoaMinimum();

            //list all partial NSEC3 records
            foreach (AuthZone zone in zones)
            {
                partialNSec3Records.Add(zone.GetPartialNSec3Record(_name, ttl, iterations, salt));

                int zoneLabelCount = DnsRRSIGRecordData.GetLabelCount(zone.Name);
                if (zone.Name.StartsWith("*."))
                    zoneLabelCount++; //need to consider wildcard label for ENT detection

                if ((zoneLabelCount - apexLabelCount) > 1)
                {
                    //empty non-terminal (ENT) may exists
                    string currentOwnerName = zone.Name;

                    while (true)
                    {
                        currentOwnerName = AuthZoneManager.GetParentZone(currentOwnerName);
                        if (currentOwnerName.Equals(_name, StringComparison.OrdinalIgnoreCase))
                            break;

                        //add partial NSEC3 record for ENT
                        AuthZone entZone = new PrimarySubDomainZone(null, currentOwnerName); //dummy empty non-terminal (ENT) sub domain object
                        partialNSec3Records.Add(entZone.GetPartialNSec3Record(_name, ttl, iterations, salt));
                    }
                }
            }

            //sort partial NSEC3 records
            partialNSec3Records.Sort(delegate (DnsResourceRecord rr1, DnsResourceRecord rr2)
            {
                return string.CompareOrdinal(rr1.Name, rr2.Name);
            });

            //deduplicate partial NSEC3 records and insert next hashed owner name to complete them
            List<DnsResourceRecord> uniqueNSec3Records = new List<DnsResourceRecord>(partialNSec3Records.Count);

            for (int i = 0; i < partialNSec3Records.Count; i++)
            {
                DnsResourceRecord partialNSec3Record = partialNSec3Records[i];
                DnsResourceRecord nextPartialNSec3Record;

                if (i < partialNSec3Records.Count - 1)
                {
                    nextPartialNSec3Record = partialNSec3Records[i + 1];

                    //check for duplicates
                    if (partialNSec3Record.Name.Equals(nextPartialNSec3Record.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        //found duplicate; merge current nsec3 into next nsec3
                        DnsNSEC3RecordData nsec3 = partialNSec3Record.RDATA as DnsNSEC3RecordData;
                        DnsNSEC3RecordData nextNSec3 = nextPartialNSec3Record.RDATA as DnsNSEC3RecordData;

                        List<DnsResourceRecordType> uniqueTypes = new List<DnsResourceRecordType>(nsec3.Types.Count + nextNSec3.Types.Count);
                        uniqueTypes.AddRange(nsec3.Types);

                        foreach (DnsResourceRecordType type in nextNSec3.Types)
                        {
                            if (!uniqueTypes.Contains(type))
                                uniqueTypes.Add(type);
                        }

                        uniqueTypes.Sort();

                        //update the next nsec3 record and continue
                        DnsNSEC3RecordData mergedPartialNSec3 = new DnsNSEC3RecordData(DnssecNSEC3HashAlgorithm.SHA1, DnssecNSEC3Flags.None, iterations, salt, Array.Empty<byte>(), uniqueTypes);
                        partialNSec3Records[i + 1] = new DnsResourceRecord(partialNSec3Record.Name, DnsResourceRecordType.NSEC3, DnsClass.IN, ttl, mergedPartialNSec3);
                        continue;
                    }
                }
                else
                {
                    //for last NSEC3, next NSEC3 is the first in list
                    nextPartialNSec3Record = partialNSec3Records[0];
                }

                //add NSEC3 record with next hashed owner name
                {
                    DnsNSEC3RecordData partialNSec3 = partialNSec3Record.RDATA as DnsNSEC3RecordData;
                    byte[] nextHashedOwnerName = DnsNSEC3RecordData.GetHashedOwnerNameFrom(nextPartialNSec3Record.Name);

                    DnsNSEC3RecordData updatedNSec3 = new DnsNSEC3RecordData(DnssecNSEC3HashAlgorithm.SHA1, DnssecNSEC3Flags.None, iterations, salt, nextHashedOwnerName, partialNSec3.Types);
                    uniqueNSec3Records.Add(new DnsResourceRecord(partialNSec3Record.Name, DnsResourceRecordType.NSEC3, DnsClass.IN, ttl, updatedNSec3));
                }
            }

            //insert and sign NSEC3 records
            foreach (DnsResourceRecord uniqueNSec3Record in uniqueNSec3Records)
            {
                AuthZone zone = _dnsServer.AuthZoneManager.GetOrAddSubDomainZone(_name, uniqueNSec3Record.Name);

                DnsResourceRecord[] newNSec3Records = new DnsResourceRecord[] { uniqueNSec3Record };

                if (!zone.TrySetRecords(DnsResourceRecordType.NSEC3, newNSec3Records, out IReadOnlyList<DnsResourceRecord> deletedNSec3Records))
                    throw new InvalidOperationException();

                addedRecords.AddRange(newNSec3Records);
                deletedRecords.AddRange(deletedNSec3Records);

                IReadOnlyList<DnsResourceRecord> newRRSigRecords = SignRRSet(newNSec3Records);
                if (newRRSigRecords.Count > 0)
                {
                    zone.AddOrUpdateRRSigRecords(newRRSigRecords, out IReadOnlyList<DnsResourceRecord> deletedRRSigRecords);

                    addedRecords.AddRange(newRRSigRecords);
                    deletedRecords.AddRange(deletedRRSigRecords);
                }
            }

            //insert and sign NSEC3PARAM record
            {
                DnsNSEC3PARAMRecordData newNSec3Param = new DnsNSEC3PARAMRecordData(DnssecNSEC3HashAlgorithm.SHA1, DnssecNSEC3Flags.None, iterations, salt);
                DnsResourceRecord[] newNSec3ParamRecords = new DnsResourceRecord[] { new DnsResourceRecord(_name, DnsResourceRecordType.NSEC3PARAM, DnsClass.IN, ttl, newNSec3Param) };

                if (!TrySetRecords(DnsResourceRecordType.NSEC3PARAM, newNSec3ParamRecords, out IReadOnlyList<DnsResourceRecord> deletedNSec3ParamRecords))
                    throw new InvalidOperationException();

                addedRecords.AddRange(newNSec3ParamRecords);
                deletedRecords.AddRange(deletedNSec3ParamRecords);

                IReadOnlyList<DnsResourceRecord> newRRSigRecords = SignRRSet(newNSec3ParamRecords);
                if (newRRSigRecords.Count > 0)
                {
                    AddOrUpdateRRSigRecords(newRRSigRecords, out IReadOnlyList<DnsResourceRecord> deletedRRSigRecords);

                    addedRecords.AddRange(newRRSigRecords);
                    deletedRecords.AddRange(deletedRRSigRecords);
                }
            }

            CommitAndIncrementSerial(deletedRecords, addedRecords);
        }

        private void DisableNSec3(IReadOnlyList<AuthZone> zones)
        {
            List<DnsResourceRecord> deletedRecords = new List<DnsResourceRecord>();

            foreach (AuthZone zone in zones)
            {
                deletedRecords.AddRange(zone.RemoveNSec3RecordsWithRRSig());

                if (zone is SubDomainZone subDomainZone)
                {
                    if (zone.IsEmpty)
                        _dnsServer.AuthZoneManager.RemoveSubDomainZone(zone.Name); //remove empty sub zone
                    else
                        subDomainZone.AutoUpdateState();
                }
            }

            CommitAndIncrementSerial(deletedRecords);
        }

        public DnssecPrivateKey GenerateAndAddPrivateKey(DnssecPrivateKeyType keyType, DnssecAlgorithm algorithm, ushort rolloverDays, int keySize = -1)
        {
            if (_dnssecStatus == AuthZoneDnssecStatus.Unsigned)
                throw new DnsServerException("The primary zone must be signed.");

            int i = 0;
            while (i++ < 5)
            {
                DnssecPrivateKey privateKey = DnssecPrivateKey.Create(algorithm, keyType, keySize);
                privateKey.RolloverDays = rolloverDays;

                lock (_dnssecPrivateKeys)
                {
                    if (_dnssecPrivateKeys.TryAdd(privateKey.KeyTag, privateKey))
                        return privateKey;
                }
            }

            throw new DnsServerException("Failed to add private key: key tag collision. Please try again.");
        }

        public void AddPrivateKey(DnssecPrivateKey privateKey)
        {
            if (_dnssecStatus == AuthZoneDnssecStatus.Unsigned)
                throw new DnsServerException("The primary zone must be signed.");

            lock (_dnssecPrivateKeys)
            {
                if (!_dnssecPrivateKeys.TryAdd(privateKey.KeyTag, privateKey))
                    throw new DnsServerException($"Failed to add {(privateKey.KeyType == DnssecPrivateKeyType.KeySigningKey ? "KSK" : "ZSK")} private key: key tag collision. Please generate another private key and try again.");
            }
        }

        public DnssecPrivateKey UpdatePrivateKey(ushort keyTag, ushort rolloverDays)
        {
            lock (_dnssecPrivateKeys)
            {
                if (!_dnssecPrivateKeys.TryGetValue(keyTag, out DnssecPrivateKey privateKey))
                    throw new DnsServerException("Cannot update private key: no such private key was found.");

                privateKey.RolloverDays = rolloverDays;

                return privateKey;
            }
        }

        public void DeletePrivateKey(ushort keyTag)
        {
            if (_dnssecStatus == AuthZoneDnssecStatus.Unsigned)
                throw new DnsServerException("The zone must be signed.");

            lock (_dnssecPrivateKeys)
            {
                if (!_dnssecPrivateKeys.TryGetValue(keyTag, out DnssecPrivateKey privateKey))
                    throw new DnsServerException("Cannot delete private key: no such private key was found.");

                if (privateKey.State != DnssecPrivateKeyState.Generated)
                    throw new DnsServerException("Cannot delete private key: only keys with Generated state can be deleted.");

                _dnssecPrivateKeys.Remove(keyTag);
            }
        }

        public void PublishAllGeneratedKeys()
        {
            if (_dnssecStatus == AuthZoneDnssecStatus.Unsigned)
                throw new DnsServerException("The zone must be signed.");

            List<DnssecPrivateKey> generatedPrivateKeys = new List<DnssecPrivateKey>();
            List<DnsResourceRecord> newDnsKeyRecords = new List<DnsResourceRecord>();

            uint dnsKeyTtl = GetDnsKeyTtl();

            lock (_dnssecPrivateKeys)
            {
                foreach (KeyValuePair<ushort, DnssecPrivateKey> privateKeyEntry in _dnssecPrivateKeys)
                {
                    DnssecPrivateKey privateKey = privateKeyEntry.Value;

                    if (privateKey.State == DnssecPrivateKeyState.Generated)
                    {
                        generatedPrivateKeys.Add(privateKey);
                        newDnsKeyRecords.Add(new DnsResourceRecord(_name, DnsResourceRecordType.DNSKEY, DnsClass.IN, dnsKeyTtl, privateKey.DnsKey));
                    }
                }
            }

            if (generatedPrivateKeys.Count == 0)
                throw new DnsServerException("Cannot publish DNSKEY: no generated private keys were found.");

            IReadOnlyList<DnsResourceRecord> dnsKeyRecords = _entries.AddOrUpdate(DnsResourceRecordType.DNSKEY, delegate (DnsResourceRecordType key)
            {
                return newDnsKeyRecords;
            },
            delegate (DnsResourceRecordType key, IReadOnlyList<DnsResourceRecord> existingRecords)
            {
                foreach (DnsResourceRecord existingRecord in existingRecords)
                {
                    foreach (DnsResourceRecord newDnsKeyRecord in newDnsKeyRecords)
                    {
                        if (existingRecord.Equals(newDnsKeyRecord))
                            throw new DnsServerException("Cannot publish DNSKEY: the key is already published.");
                    }
                }

                List<DnsResourceRecord> dnsKeyRecords = new List<DnsResourceRecord>(existingRecords.Count + newDnsKeyRecords.Count);

                dnsKeyRecords.AddRange(existingRecords);
                dnsKeyRecords.AddRange(newDnsKeyRecords);

                return dnsKeyRecords;
            });

            //update private key state before signing
            uint propagationDelay = GetPropagationDelay();

            foreach (DnssecPrivateKey privateKey in generatedPrivateKeys)
                privateKey.SetState(DnssecPrivateKeyState.Published, dnsKeyTtl + propagationDelay);

            List<DnsResourceRecord> addedRecords = new List<DnsResourceRecord>();
            List<DnsResourceRecord> deletedRecords = new List<DnsResourceRecord>();

            addedRecords.AddRange(newDnsKeyRecords);

            IReadOnlyList<DnsResourceRecord> newRRSigRecords = SignRRSet(dnsKeyRecords);
            if (newRRSigRecords.Count > 0)
            {
                AddOrUpdateRRSigRecords(newRRSigRecords, out IReadOnlyList<DnsResourceRecord> deletedRRSigRecords);

                addedRecords.AddRange(newRRSigRecords);
                deletedRecords.AddRange(deletedRRSigRecords);
            }

            CommitAndIncrementSerial(deletedRecords, addedRecords);
            TriggerNotify();
        }

        private void ActivateZskDnsKeys(IReadOnlyList<DnssecPrivateKey> zskPrivateKeys)
        {
            List<DnsResourceRecord> addedRecords = new List<DnsResourceRecord>();
            List<DnsResourceRecord> deletedRecords = new List<DnsResourceRecord>();

            //re-sign all records with new private keys
            IReadOnlyList<AuthZone> zones = _dnsServer.AuthZoneManager.GetApexZoneWithSubDomainZones(_name);

            foreach (AuthZone zone in zones)
            {
                IReadOnlyList<DnsResourceRecord> newRRSigRecords = zone.SignAllRRSets();
                if (newRRSigRecords.Count > 0)
                {
                    zone.AddOrUpdateRRSigRecords(newRRSigRecords, out IReadOnlyList<DnsResourceRecord> deletedRRSigRecords);

                    addedRecords.AddRange(newRRSigRecords);
                    deletedRecords.AddRange(deletedRRSigRecords);
                }
            }

            CommitAndIncrementSerial(deletedRecords, addedRecords);
            TriggerNotify();

            //update private key state
            string dnsKeyTags = null;

            foreach (DnssecPrivateKey privateKey in zskPrivateKeys)
            {
                privateKey.SetState(DnssecPrivateKeyState.Active);

                if (dnsKeyTags is null)
                    dnsKeyTags = privateKey.KeyTag.ToString();
                else
                    dnsKeyTags += ", " + privateKey.KeyTag.ToString();
            }

            _dnsServer.LogManager.Write("The ZSK DNSKEYs (" + dnsKeyTags + ") from the primary zone were activated successfully: " + ToString());
        }

        public void RolloverDnsKey(ushort keyTag)
        {
            if (_dnssecStatus == AuthZoneDnssecStatus.Unsigned)
                throw new DnsServerException("The zone must be signed.");

            DnssecPrivateKey privateKey;

            lock (_dnssecPrivateKeys)
            {
                if (!_dnssecPrivateKeys.TryGetValue(keyTag, out privateKey))
                    throw new DnsServerException("Cannot rollover private key: no such private key was found.");
            }

            switch (privateKey.State)
            {
                case DnssecPrivateKeyState.Ready:
                case DnssecPrivateKeyState.Active:
                    if (privateKey.IsRetiring)
                        throw new DnsServerException("Cannot rollover private key: the private key is already set to retire.");

                    break;

                default:
                    throw new DnsServerException("Cannot rollover private key: the private key state must be Ready or Active to be able to rollover.");
            }

            switch (privateKey.Algorithm)
            {
                case DnssecAlgorithm.RSAMD5:
                case DnssecAlgorithm.RSASHA1:
                case DnssecAlgorithm.RSASHA1_NSEC3_SHA1:
                case DnssecAlgorithm.RSASHA256:
                case DnssecAlgorithm.RSASHA512:
                    GenerateAndAddPrivateKey(privateKey.KeyType, privateKey.Algorithm, privateKey.RolloverDays, (privateKey as DnssecRsaPrivateKey).KeySize);
                    break;

                case DnssecAlgorithm.ECDSAP256SHA256:
                case DnssecAlgorithm.ECDSAP384SHA384:
                case DnssecAlgorithm.ED25519:
                case DnssecAlgorithm.ED448:
                    GenerateAndAddPrivateKey(privateKey.KeyType, privateKey.Algorithm, privateKey.RolloverDays);
                    break;

                default:
                    throw new NotSupportedException("DNSSEC algorithm is not supported: " + privateKey.Algorithm.ToString());
            }

            PublishAllGeneratedKeys();
            privateKey.SetToRetire();
        }

        public async Task RetireDnsKeyAsync(ushort keyTag)
        {
            if (_dnssecStatus == AuthZoneDnssecStatus.Unsigned)
                throw new DnsServerException("The zone must be signed.");

            DnssecPrivateKey privateKeyToRetire;

            lock (_dnssecPrivateKeys)
            {
                if (!_dnssecPrivateKeys.TryGetValue(keyTag, out privateKeyToRetire))
                    throw new DnsServerException("Cannot retire private key: no such private key was found.");
            }

            switch (privateKeyToRetire.KeyType)
            {
                case DnssecPrivateKeyType.KeySigningKey:
                    switch (privateKeyToRetire.State)
                    {
                        case DnssecPrivateKeyState.Ready:
                        case DnssecPrivateKeyState.Active:
                            if (!await RetireKskDnsKeysAsync([privateKeyToRetire], true))
                                throw new DnsServerException("Cannot retire private key: no successor key was found to safely retire the key.");

                            break;

                        default:
                            throw new DnsServerException("Cannot retire private key: the KSK private key state must be Ready or Active to be able to retire.");
                    }
                    break;

                case DnssecPrivateKeyType.ZoneSigningKey:
                    switch (privateKeyToRetire.State)
                    {
                        case DnssecPrivateKeyState.Active:
                            if (!RetireZskDnsKeys(new DnssecPrivateKey[] { privateKeyToRetire }, true))
                                throw new DnsServerException("Cannot retire private key: no successor key was found to safely retire the key.");

                            break;

                        default:
                            throw new DnsServerException("Cannot retire private key: the ZSK private key state must be Active to be able to retire.");
                    }
                    break;

                default:
                    throw new InvalidOperationException();
            }
        }

        private async Task<bool> RetireKskDnsKeysAsync(IReadOnlyList<DnssecPrivateKey> kskPrivateKeys, bool ignoreAlgorithm)
        {
            string dnsKeyTags = null;
            uint dsTtl = 0;
            uint parentSidePropagationDelay = 0;

            foreach (DnssecPrivateKey kskPrivateKey in kskPrivateKeys)
            {
                bool isSafeToRetire = false;

                lock (_dnssecPrivateKeys)
                {
                    foreach (KeyValuePair<ushort, DnssecPrivateKey> privateKeyEntry in _dnssecPrivateKeys)
                    {
                        DnssecPrivateKey privateKey = privateKeyEntry.Value;

                        if ((privateKey.KeyType == DnssecPrivateKeyType.KeySigningKey) && (privateKey.KeyTag != kskPrivateKey.KeyTag) && !privateKey.IsRetiring)
                        {
                            if (ignoreAlgorithm)
                            {
                                //manual retire case
                                if (privateKey.Algorithm != kskPrivateKey.Algorithm)
                                {
                                    //check if the sucessor ksk has a matching zsk
                                    bool foundMatchingZsk = false;

                                    foreach (KeyValuePair<ushort, DnssecPrivateKey> zskPrivateKeyEntry in _dnssecPrivateKeys)
                                    {
                                        DnssecPrivateKey zskPrivateKey = zskPrivateKeyEntry.Value;

                                        if ((zskPrivateKey.KeyType == DnssecPrivateKeyType.ZoneSigningKey) && (zskPrivateKey.Algorithm == privateKey.Algorithm) && (zskPrivateKey.State == DnssecPrivateKeyState.Active) && !zskPrivateKey.IsRetiring)
                                        {
                                            foundMatchingZsk = true;
                                            break;
                                        }
                                    }

                                    if (!foundMatchingZsk)
                                        continue;
                                }
                            }
                            else
                            {
                                //rollover case
                                if (privateKey.Algorithm != kskPrivateKey.Algorithm)
                                    continue;
                            }

                            if (privateKey.State == DnssecPrivateKeyState.Active)
                            {
                                isSafeToRetire = true;
                                break;
                            }

                            if ((privateKey.State == DnssecPrivateKeyState.Ready) && (kskPrivateKey.State == DnssecPrivateKeyState.Ready))
                            {
                                isSafeToRetire = true;
                                break;
                            }
                        }
                    }
                }

                if (isSafeToRetire)
                {
                    if (dsTtl == 0)
                        dsTtl = await GetDSTtlAsync();

                    if (parentSidePropagationDelay == 0)
                        parentSidePropagationDelay = await GetParentSidePropagationDelayAsync();

                    kskPrivateKey.SetState(DnssecPrivateKeyState.Retired, dsTtl + parentSidePropagationDelay);

                    if (dnsKeyTags is null)
                        dnsKeyTags = kskPrivateKey.KeyTag.ToString();
                    else
                        dnsKeyTags += ", " + kskPrivateKey.KeyTag.ToString();
                }
            }

            if (dnsKeyTags is not null)
            {
                _dnsServer.LogManager.Write("The KSK DNSKEYs (" + dnsKeyTags + ") from the primary zone were retired successfully: " + ToString());

                return true;
            }

            return false;
        }

        private bool RetireZskDnsKeys(IReadOnlyList<DnssecPrivateKey> zskPrivateKeys, bool ignoreAlgorithm)
        {
            string dnsKeyTags = null;
            List<DnssecPrivateKey> zskToDeactivate = null;
            uint maxRRSigTtl = 0;
            uint propagationDelay = 0;

            foreach (DnssecPrivateKey zskPrivateKey in zskPrivateKeys)
            {
                bool isSafeToRetire = false;

                lock (_dnssecPrivateKeys)
                {
                    foreach (KeyValuePair<ushort, DnssecPrivateKey> privateKeyEntry in _dnssecPrivateKeys)
                    {
                        DnssecPrivateKey privateKey = privateKeyEntry.Value;

                        if ((privateKey.KeyType == DnssecPrivateKeyType.ZoneSigningKey) && (privateKey.KeyTag != zskPrivateKey.KeyTag) && (privateKey.State == DnssecPrivateKeyState.Active) && !privateKey.IsRetiring)
                        {
                            if (ignoreAlgorithm)
                            {
                                //manual retire case
                                if (privateKey.Algorithm != zskPrivateKey.Algorithm)
                                {
                                    //check if the sucessor zsk has a matching ksk
                                    bool foundMatchingKsk = false;

                                    foreach (KeyValuePair<ushort, DnssecPrivateKey> kskPrivateKeyEntry in _dnssecPrivateKeys)
                                    {
                                        DnssecPrivateKey kskPrivateKey = kskPrivateKeyEntry.Value;

                                        if ((kskPrivateKey.KeyType == DnssecPrivateKeyType.KeySigningKey) && (kskPrivateKey.Algorithm == privateKey.Algorithm) && ((kskPrivateKey.State == DnssecPrivateKeyState.Ready) || (kskPrivateKey.State == DnssecPrivateKeyState.Active)) && !kskPrivateKey.IsRetiring)
                                        {
                                            foundMatchingKsk = true;
                                            break;
                                        }
                                    }

                                    if (!foundMatchingKsk)
                                        continue;
                                }
                            }
                            else
                            {
                                //rollover case
                                if (privateKey.Algorithm != zskPrivateKey.Algorithm)
                                    continue;
                            }

                            isSafeToRetire = true;
                            break;
                        }
                    }
                }

                if (isSafeToRetire)
                {
                    if (maxRRSigTtl == 0)
                        maxRRSigTtl = GetMaxRRSigTtl();

                    if (propagationDelay == 0)
                        propagationDelay = GetPropagationDelay();

                    zskPrivateKey.SetState(DnssecPrivateKeyState.Retired, maxRRSigTtl + propagationDelay);

                    if (zskToDeactivate is null)
                        zskToDeactivate = new List<DnssecPrivateKey>();

                    zskToDeactivate.Add(zskPrivateKey);

                    if (dnsKeyTags is null)
                        dnsKeyTags = zskPrivateKey.KeyTag.ToString();
                    else
                        dnsKeyTags += ", " + zskPrivateKey.KeyTag.ToString();
                }
            }

            if (zskToDeactivate is not null)
                DeactivateZskDnsKeys(zskToDeactivate);

            if (dnsKeyTags is not null)
            {
                _dnsServer.LogManager.Write("The ZSK DNSKEYs (" + dnsKeyTags + ") from the primary zone were retired successfully: " + ToString());

                return true;
            }

            return false;
        }

        private void DeactivateZskDnsKeys(IReadOnlyList<DnssecPrivateKey> zskPrivateKeys)
        {
            //remove all RRSIGs for the DNSKEYs
            List<DnsResourceRecord> deletedRecords = new List<DnsResourceRecord>();

            IReadOnlyList<AuthZone> zones = _dnsServer.AuthZoneManager.GetApexZoneWithSubDomainZones(_name);

            foreach (AuthZone zone in zones)
            {
                IReadOnlyList<DnsResourceRecord> rrsigRecords = zone.GetRecords(DnsResourceRecordType.RRSIG);
                List<DnsResourceRecord> rrsigsToRemove = new List<DnsResourceRecord>();

                foreach (DnsResourceRecord rrsigRecord in rrsigRecords)
                {
                    DnsRRSIGRecordData rrsig = rrsigRecord.RDATA as DnsRRSIGRecordData;

                    foreach (DnssecPrivateKey privateKey in zskPrivateKeys)
                    {
                        if (rrsig.KeyTag == privateKey.KeyTag)
                        {
                            rrsigsToRemove.Add(rrsigRecord);
                            break;
                        }
                    }
                }

                if (zone.TryDeleteRecords(DnsResourceRecordType.RRSIG, rrsigsToRemove, out IReadOnlyList<DnsResourceRecord> deletedRRSigRecords))
                    deletedRecords.AddRange(deletedRRSigRecords);
            }

            CommitAndIncrementSerial(deletedRecords);
            TriggerNotify();

            string dnsKeyTags = null;

            foreach (DnssecPrivateKey privateKey in zskPrivateKeys)
            {
                if (dnsKeyTags is null)
                    dnsKeyTags = privateKey.KeyTag.ToString();
                else
                    dnsKeyTags += ", " + privateKey.KeyTag.ToString();
            }

            _dnsServer.LogManager.Write("The ZSK DNSKEYs (" + dnsKeyTags + ") from the primary zone were deactivated successfully: " + ToString());
        }

        private void RevokeKskDnsKeys(List<DnssecPrivateKey> kskPrivateKeys)
        {
            if (!_entries.TryGetValue(DnsResourceRecordType.DNSKEY, out IReadOnlyList<DnsResourceRecord> existingDnsKeyRecords))
                throw new InvalidOperationException();

            List<DnsResourceRecord> addedRecords = new List<DnsResourceRecord>();
            List<DnsResourceRecord> deletedRecords = new List<DnsResourceRecord>();

            List<DnsResourceRecord> dnsKeyRecords = new List<DnsResourceRecord>();

            foreach (DnsResourceRecord existingDnsKeyRecord in existingDnsKeyRecords)
            {
                bool found = false;

                foreach (DnssecPrivateKey privateKey in kskPrivateKeys)
                {
                    if (existingDnsKeyRecord.RDATA.Equals(privateKey.DnsKey))
                    {
                        found = true;
                        break;
                    }
                }

                if (!found)
                    dnsKeyRecords.Add(existingDnsKeyRecord);
            }

            uint dnsKeyTtl = existingDnsKeyRecords[0].OriginalTtlValue;
            List<ushort> keyTagsToRemove = new List<ushort>(kskPrivateKeys.Count);

            //rfc7583#section-3.3.4
            //modifiedQueryInterval = MAX(1hr, MIN(15 days, TTLkey / 2)) 
            uint modifiedQueryInterval = Math.Max(3600u, Math.Min(15 * 24 * 60 * 60, dnsKeyTtl / 2));

            foreach (DnssecPrivateKey privateKey in kskPrivateKeys)
            {
                keyTagsToRemove.Add(privateKey.KeyTag);
                privateKey.SetState(DnssecPrivateKeyState.Revoked, modifiedQueryInterval);

                DnsResourceRecord revokedDnsKeyRecord = new DnsResourceRecord(_name, DnsResourceRecordType.DNSKEY, DnsClass.IN, dnsKeyTtl, privateKey.DnsKey);
                dnsKeyRecords.Add(revokedDnsKeyRecord);
            }

            if (!TrySetRecords(DnsResourceRecordType.DNSKEY, dnsKeyRecords, out IReadOnlyList<DnsResourceRecord> deletedDnsKeyRecords))
                throw new InvalidOperationException();

            addedRecords.AddRange(dnsKeyRecords);
            deletedRecords.AddRange(deletedDnsKeyRecords);

            IReadOnlyList<DnsResourceRecord> newRRSigRecords = SignRRSet(dnsKeyRecords);
            if (newRRSigRecords.Count > 0)
            {
                AddOrUpdateRRSigRecords(newRRSigRecords, out IReadOnlyList<DnsResourceRecord> deletedRRSigRecords);

                addedRecords.AddRange(newRRSigRecords);
                deletedRecords.AddRange(deletedRRSigRecords);
            }

            //remove RRSIG for removed keys
            {
                IReadOnlyList<DnsResourceRecord> rrsigRecords = GetRecords(DnsResourceRecordType.RRSIG);
                List<DnsResourceRecord> rrsigsToRemove = new List<DnsResourceRecord>();

                foreach (DnsResourceRecord rrsigRecord in rrsigRecords)
                {
                    DnsRRSIGRecordData rrsig = rrsigRecord.RDATA as DnsRRSIGRecordData;
                    if (rrsig.TypeCovered != DnsResourceRecordType.DNSKEY)
                        continue;

                    foreach (ushort keyTagToRemove in keyTagsToRemove)
                    {
                        if (rrsig.KeyTag == keyTagToRemove)
                        {
                            rrsigsToRemove.Add(rrsigRecord);
                            break;
                        }
                    }
                }

                if (TryDeleteRecords(DnsResourceRecordType.RRSIG, rrsigsToRemove, out IReadOnlyList<DnsResourceRecord> deletedRRSigRecords))
                    deletedRecords.AddRange(deletedRRSigRecords);
            }

            CommitAndIncrementSerial(deletedRecords, addedRecords);
            TriggerNotify();

            //update revoked private keys
            string dnsKeyTags = null;

            lock (_dnssecPrivateKeys)
            {
                //remove old entry
                foreach (ushort keyTag in keyTagsToRemove)
                {
                    if (_dnssecPrivateKeys.Remove(keyTag))
                    {
                        if (dnsKeyTags is null)
                            dnsKeyTags = keyTag.ToString();
                        else
                            dnsKeyTags += ", " + keyTag.ToString();
                    }
                }

                //add new entry
                foreach (DnssecPrivateKey privateKey in kskPrivateKeys)
                    _dnssecPrivateKeys.Add(privateKey.KeyTag, privateKey);
            }

            _dnsServer.LogManager.Write("The KSK DNSKEYs (" + dnsKeyTags + ") from the primary zone were revoked successfully: " + ToString());
        }

        private void UnpublishDnsKeys(IReadOnlyList<DnssecPrivateKey> deadPrivateKeys)
        {
            if (!_entries.TryGetValue(DnsResourceRecordType.DNSKEY, out IReadOnlyList<DnsResourceRecord> existingDnsKeyRecords))
                throw new InvalidOperationException();

            List<DnsResourceRecord> addedRecords = new List<DnsResourceRecord>();
            List<DnsResourceRecord> deletedRecords = new List<DnsResourceRecord>();

            List<DnsResourceRecord> dnsKeyRecords = new List<DnsResourceRecord>();

            foreach (DnsResourceRecord existingDnsKeyRecord in existingDnsKeyRecords)
            {
                bool found = false;

                foreach (DnssecPrivateKey privateKey in deadPrivateKeys)
                {
                    if (existingDnsKeyRecord.RDATA.Equals(privateKey.DnsKey))
                    {
                        found = true;
                        break;
                    }
                }

                if (!found)
                    dnsKeyRecords.Add(existingDnsKeyRecord);
            }

            if (dnsKeyRecords.Count < 2)
                throw new InvalidOperationException();

            if (!TrySetRecords(DnsResourceRecordType.DNSKEY, dnsKeyRecords, out IReadOnlyList<DnsResourceRecord> deletedDnsKeyRecords))
                throw new InvalidOperationException();

            addedRecords.AddRange(dnsKeyRecords);
            deletedRecords.AddRange(deletedDnsKeyRecords);

            IReadOnlyList<DnsResourceRecord> newRRSigRecords = SignRRSet(dnsKeyRecords);
            if (newRRSigRecords.Count > 0)
            {
                AddOrUpdateRRSigRecords(newRRSigRecords, out IReadOnlyList<DnsResourceRecord> deletedRRSigRecords);

                addedRecords.AddRange(newRRSigRecords);
                deletedRecords.AddRange(deletedRRSigRecords);
            }

            //remove RRSig for revoked keys
            {
                IReadOnlyList<DnsResourceRecord> rrsigRecords = GetRecords(DnsResourceRecordType.RRSIG);
                List<DnsResourceRecord> rrsigsToRemove = new List<DnsResourceRecord>();

                foreach (DnsResourceRecord rrsigRecord in rrsigRecords)
                {
                    DnsRRSIGRecordData rrsig = rrsigRecord.RDATA as DnsRRSIGRecordData;
                    if (rrsig.TypeCovered != DnsResourceRecordType.DNSKEY)
                        continue;

                    foreach (DnssecPrivateKey privateKey in deadPrivateKeys)
                    {
                        if (rrsig.KeyTag == privateKey.KeyTag)
                        {
                            rrsigsToRemove.Add(rrsigRecord);
                            break;
                        }
                    }
                }

                if (TryDeleteRecords(DnsResourceRecordType.RRSIG, rrsigsToRemove, out IReadOnlyList<DnsResourceRecord> deletedRRSigRecords))
                    deletedRecords.AddRange(deletedRRSigRecords);
            }

            CommitAndIncrementSerial(deletedRecords, addedRecords);
            TriggerNotify();

            //remove private keys permanently
            string dnsKeyTags = null;

            lock (_dnssecPrivateKeys)
            {
                foreach (DnssecPrivateKey privateKey in deadPrivateKeys)
                {
                    if (_dnssecPrivateKeys.Remove(privateKey.KeyTag))
                    {
                        if (dnsKeyTags is null)
                            dnsKeyTags = privateKey.KeyTag.ToString();
                        else
                            dnsKeyTags += ", " + privateKey.KeyTag.ToString();
                    }
                }
            }

            _dnsServer.LogManager.Write("The DNSKEYs (" + dnsKeyTags + ") from the primary zone were unpublished successfully: " + ToString());
        }

        private async Task<IReadOnlyList<DnssecPrivateKey>> GetDSPublishedPrivateKeysAsync(IReadOnlyList<DnssecPrivateKey> privateKeys, CancellationToken cancellationToken = default)
        {
            if (_name.Length == 0)
                return privateKeys; //zone is root

            //delete any existing DS entries from cache to allow resolving latest ones
            _dnsServer.CacheZoneManager.DeleteZone(_name);

            DirectDnsClient dnsClient = new DirectDnsClient(_dnsServer);
            dnsClient.DnssecValidation = true;
            dnsClient.Timeout = 10000;

            IReadOnlyList<DnsDSRecordData> dsRecords;

            try
            {
                dsRecords = DnsClient.ParseResponseDS(await dnsClient.ResolveAsync(new DnsQuestionRecord(_name, DnsResourceRecordType.DS, DnsClass.IN), cancellationToken: cancellationToken));
            }
            catch
            {
                //suppress exception here to avoid filling log file
                return [];
            }

            List<DnssecPrivateKey> activePrivateKeys = new List<DnssecPrivateKey>(dsRecords.Count);

            foreach (DnsDSRecordData dsRecord in dsRecords)
            {
                foreach (DnssecPrivateKey privateKey in privateKeys)
                {
                    if ((dsRecord.KeyTag == privateKey.DnsKey.ComputedKeyTag) && (dsRecord.Algorithm == privateKey.DnsKey.Algorithm) && privateKey.DnsKey.IsDnsKeyValid(_name, dsRecord))
                    {
                        activePrivateKeys.Add(privateKey);
                        break;
                    }
                }
            }

            return activePrivateKeys;
        }

        private bool TryRefreshAllSignatures()
        {
            List<DnsResourceRecord> addedRecords = new List<DnsResourceRecord>();
            List<DnsResourceRecord> deletedRecords = new List<DnsResourceRecord>();

            IReadOnlyList<AuthZone> zones = _dnsServer.AuthZoneManager.GetApexZoneWithSubDomainZones(_name);

            foreach (AuthZone zone in zones)
            {
                IReadOnlyList<DnsResourceRecord> newRRSigRecords = zone.RefreshSignatures();
                if (newRRSigRecords.Count > 0)
                {
                    zone.AddOrUpdateRRSigRecords(newRRSigRecords, out IReadOnlyList<DnsResourceRecord> deletedRRSigRecords);

                    addedRecords.AddRange(newRRSigRecords);
                    deletedRecords.AddRange(deletedRRSigRecords);
                }
            }

            if ((deletedRecords.Count > 0) || (addedRecords.Count > 0))
            {
                CommitAndIncrementSerial(deletedRecords, addedRecords);
                TriggerNotify();

                return true;
            }

            return false;
        }

        internal override IReadOnlyList<DnsResourceRecord> SignRRSet(IReadOnlyList<DnsResourceRecord> records)
        {
            DnsResourceRecordType rrsetType = records[0].Type;

            List<DnsResourceRecord> rrsigRecords = new List<DnsResourceRecord>();
            uint signatureValidityPeriod = GetSignatureValidityPeriod();

            switch (rrsetType)
            {
                case DnsResourceRecordType.DNSKEY:
                    lock (_dnssecPrivateKeys)
                    {
                        foreach (KeyValuePair<ushort, DnssecPrivateKey> privateKeyEntry in _dnssecPrivateKeys)
                        {
                            DnssecPrivateKey privateKey = privateKeyEntry.Value;
                            if (privateKey.KeyType != DnssecPrivateKeyType.KeySigningKey)
                                continue;

                            switch (privateKey.State)
                            {
                                case DnssecPrivateKeyState.Published:
                                case DnssecPrivateKeyState.Ready:
                                case DnssecPrivateKeyState.Active:
                                case DnssecPrivateKeyState.Revoked:
                                    rrsigRecords.Add(privateKey.SignRRSet(_name, records, DNSSEC_SIGNATURE_INCEPTION_OFFSET, signatureValidityPeriod));
                                    break;
                            }
                        }
                    }
                    break;

                case DnsResourceRecordType.RRSIG:
                    throw new InvalidOperationException();

                case DnsResourceRecordType.ANAME:
                case DnsResourceRecordType.APP:
                    throw new DnsServerException("Cannot sign RRSet: The record type [" + rrsetType.ToString() + "] is not supported by DNSSEC signed primary zones.");

                default:
                    if ((rrsetType == DnsResourceRecordType.NS) && (records[0].Name.Length > _name.Length))
                        return Array.Empty<DnsResourceRecord>(); //referrer NS records are not signed

                    foreach (DnsResourceRecord record in records)
                    {
                        if (record.GetAuthGenericRecordInfo().Disabled)
                            throw new DnsServerException("Cannot sign RRSet: Signing disabled records is not supported.");
                    }

                    lock (_dnssecPrivateKeys)
                    {
                        foreach (KeyValuePair<ushort, DnssecPrivateKey> privateKeyEntry in _dnssecPrivateKeys)
                        {
                            DnssecPrivateKey privateKey = privateKeyEntry.Value;
                            if (privateKey.KeyType != DnssecPrivateKeyType.ZoneSigningKey)
                                continue;

                            switch (privateKey.State)
                            {
                                case DnssecPrivateKeyState.Ready:
                                case DnssecPrivateKeyState.Active:
                                    rrsigRecords.Add(privateKey.SignRRSet(_name, records, DNSSEC_SIGNATURE_INCEPTION_OFFSET, signatureValidityPeriod));
                                    break;
                            }
                        }
                    }
                    break;
            }

            if (rrsigRecords.Count == 0)
                throw new InvalidOperationException("Cannot sign RRSet: no private key was available.");

            return rrsigRecords;
        }

        internal void UpdateDnssecRecordsFor(AuthZone zone, DnsResourceRecordType type)
        {
            //lock to sync this call to prevent inconsistent NSEC/NSEC3 updates
            lock (_dnssecUpdateLock)
            {
                IReadOnlyList<DnsResourceRecord> records = zone.GetRecords(type);
                if (records.Count > 0)
                {
                    //rrset added or updated
                    //sign rrset
                    IReadOnlyList<DnsResourceRecord> newRRSigRecords = SignRRSet(records);
                    if (newRRSigRecords.Count > 0)
                    {
                        zone.AddOrUpdateRRSigRecords(newRRSigRecords, out IReadOnlyList<DnsResourceRecord> deletedRRSigRecords);

                        CommitAndIncrementSerial(deletedRRSigRecords, newRRSigRecords);
                    }
                }
                else
                {
                    //rrset deleted
                    //delete rrsig
                    IReadOnlyList<DnsResourceRecord> existingRRSigRecords = zone.GetRecords(DnsResourceRecordType.RRSIG);
                    if (existingRRSigRecords.Count > 0)
                    {
                        List<DnsResourceRecord> recordsToDelete = new List<DnsResourceRecord>();

                        foreach (DnsResourceRecord existingRRSigRecord in existingRRSigRecords)
                        {
                            DnsRRSIGRecordData rrsig = existingRRSigRecord.RDATA as DnsRRSIGRecordData;
                            if (rrsig.TypeCovered == type)
                                recordsToDelete.Add(existingRRSigRecord);
                        }

                        if (zone.TryDeleteRecords(DnsResourceRecordType.RRSIG, recordsToDelete, out IReadOnlyList<DnsResourceRecord> deletedRRSigRecords))
                            CommitAndIncrementSerial(deletedRRSigRecords);
                    }
                }

                if (_dnssecStatus == AuthZoneDnssecStatus.SignedWithNSEC)
                {
                    UpdateNSecRRSetFor(zone);
                }
                else
                {
                    UpdateNSec3RRSetFor(zone);

                    int apexLabelCount = DnsRRSIGRecordData.GetLabelCount(_name);
                    int zoneLabelCount = DnsRRSIGRecordData.GetLabelCount(zone.Name);
                    if (zone.Name.StartsWith("*.") || zone.Name.Equals('*'))
                        zoneLabelCount++; //need to consider wildcard label for ENT detection

                    if ((zoneLabelCount - apexLabelCount) > 1)
                    {
                        //empty non-terminal (ENT) may exists
                        string currentOwnerName = zone.Name;

                        while (true)
                        {
                            currentOwnerName = AuthZoneManager.GetParentZone(currentOwnerName);
                            if (currentOwnerName.Equals(_name, StringComparison.OrdinalIgnoreCase))
                                break;

                            //update NSEC3 rrset for current owner name
                            AuthZone entZone = _dnsServer.AuthZoneManager.GetAuthZone(_name, currentOwnerName);
                            if (entZone is null)
                                entZone = new PrimarySubDomainZone(null, currentOwnerName); //dummy empty non-terminal (ENT) sub domain object

                            UpdateNSec3RRSetFor(entZone);
                        }
                    }
                }
            }
        }

        private void UpdateNSecRRSetFor(AuthZone zone)
        {
            uint ttl = GetZoneSoaMinimum();

            IReadOnlyList<DnsResourceRecord> newNSecRecords = GetUpdatedNSecRRSetFor(zone, ttl);
            if (newNSecRecords.Count > 0)
            {
                DnsResourceRecord newNSecRecord = newNSecRecords[0];
                DnsNSECRecordData newNSec = newNSecRecord.RDATA as DnsNSECRecordData;
                if (newNSec.Types.Count == 2)
                {
                    //only NSEC and RRSIG exists so remove NSEC
                    IReadOnlyList<DnsResourceRecord> deletedNSecRecords = zone.RemoveNSecRecordsWithRRSig();
                    if (deletedNSecRecords.Count > 0)
                        CommitAndIncrementSerial(deletedNSecRecords);

                    //relink previous nsec
                    RelinkPreviousNSecRRSetFor(newNSecRecord, ttl, true);
                }
                else
                {
                    List<DnsResourceRecord> addedRecords = new List<DnsResourceRecord>();
                    List<DnsResourceRecord> deletedRecords = new List<DnsResourceRecord>();

                    if (!zone.TrySetRecords(DnsResourceRecordType.NSEC, newNSecRecords, out IReadOnlyList<DnsResourceRecord> deletedNSecRecords))
                        throw new DnsServerException("Failed to set DNSSEC records. Please try again.");

                    addedRecords.AddRange(newNSecRecords);
                    deletedRecords.AddRange(deletedNSecRecords);

                    IReadOnlyList<DnsResourceRecord> newRRSigRecords = SignRRSet(newNSecRecords);
                    if (newRRSigRecords.Count > 0)
                    {
                        zone.AddOrUpdateRRSigRecords(newRRSigRecords, out IReadOnlyList<DnsResourceRecord> deletedRRSigRecords);

                        addedRecords.AddRange(newRRSigRecords);
                        deletedRecords.AddRange(deletedRRSigRecords);
                    }

                    CommitAndIncrementSerial(deletedRecords, addedRecords);

                    if (deletedNSecRecords.Count == 0)
                    {
                        //new NSEC created since no old NSEC was removed
                        //relink previous nsec
                        RelinkPreviousNSecRRSetFor(newNSecRecord, ttl, false);
                    }
                }
            }
        }

        private void UpdateNSec3RRSetFor(AuthZone zone)
        {
            uint ttl = GetZoneSoaMinimum();
            bool noSubDomainExistsForEmptyZone = (zone.IsEmpty || zone.HasOnlyNSec3Records()) && !_dnsServer.AuthZoneManager.SubDomainExistsFor(_name, zone.Name);

            IReadOnlyList<DnsResourceRecord> newNSec3Records = GetUpdatedNSec3RRSetFor(zone, ttl, noSubDomainExistsForEmptyZone);
            if (newNSec3Records.Count > 0)
            {
                DnsResourceRecord newNSec3Record = newNSec3Records[0];

                AuthZone nsec3Zone = _dnsServer.AuthZoneManager.GetOrAddSubDomainZone(_name, newNSec3Record.Name);
                if (nsec3Zone is null)
                    throw new InvalidOperationException();

                if (noSubDomainExistsForEmptyZone)
                {
                    //no records exists in real zone and no sub domain exists, so remove NSEC3
                    IReadOnlyList<DnsResourceRecord> deletedNSec3Records = nsec3Zone.RemoveNSec3RecordsWithRRSig();
                    if (deletedNSec3Records.Count > 0)
                        CommitAndIncrementSerial(deletedNSec3Records);

                    //remove nsec3 sub domain zone if empty since it wont get removed otherwise
                    if (nsec3Zone is SubDomainZone nsec3SubDomainZone)
                    {
                        if (nsec3Zone.IsEmpty)
                            _dnsServer.AuthZoneManager.RemoveSubDomainZone(nsec3Zone.Name); //remove empty sub zone
                        else
                            nsec3SubDomainZone.AutoUpdateState();
                    }

                    //remove the real zone if empty so that any of the ENT that exists can also be removed later
                    if (zone is SubDomainZone subDomainZone)
                    {
                        if (zone.IsEmpty)
                            _dnsServer.AuthZoneManager.RemoveSubDomainZone(zone.Name); //remove empty sub zone
                        else
                            subDomainZone.AutoUpdateState();
                    }

                    //relink previous nsec3
                    RelinkPreviousNSec3RRSet(newNSec3Record, ttl, true);
                }
                else
                {
                    List<DnsResourceRecord> addedRecords = new List<DnsResourceRecord>();
                    List<DnsResourceRecord> deletedRecords = new List<DnsResourceRecord>();

                    if (!nsec3Zone.TrySetRecords(DnsResourceRecordType.NSEC3, newNSec3Records, out IReadOnlyList<DnsResourceRecord> deletedNSec3Records))
                        throw new DnsServerException("Failed to set DNSSEC records. Please try again.");

                    addedRecords.AddRange(newNSec3Records);
                    deletedRecords.AddRange(deletedNSec3Records);

                    IReadOnlyList<DnsResourceRecord> newRRSigRecords = SignRRSet(newNSec3Records);
                    if (newRRSigRecords.Count > 0)
                    {
                        nsec3Zone.AddOrUpdateRRSigRecords(newRRSigRecords, out IReadOnlyList<DnsResourceRecord> deletedRRSigRecords);

                        addedRecords.AddRange(newRRSigRecords);
                        deletedRecords.AddRange(deletedRRSigRecords);
                    }

                    CommitAndIncrementSerial(deletedRecords, addedRecords);

                    if (deletedNSec3Records.Count == 0)
                    {
                        //new NSEC3 created since no old NSEC3 was removed
                        //relink previous nsec
                        RelinkPreviousNSec3RRSet(newNSec3Record, ttl, false);
                    }
                }
            }
        }

        private IReadOnlyList<DnsResourceRecord> GetUpdatedNSecRRSetFor(AuthZone zone, uint ttl)
        {
            AuthZone nextZone = _dnsServer.AuthZoneManager.FindNextSubDomainZone(_name, zone.Name);
            if (nextZone is null)
                nextZone = this;

            return zone.GetUpdatedNSecRRSet(nextZone.Name, ttl);
        }

        private IReadOnlyList<DnsResourceRecord> GetUpdatedNSec3RRSetFor(AuthZone zone, uint ttl, bool forceGetNewRRSet)
        {
            if (!_entries.TryGetValue(DnsResourceRecordType.NSEC3PARAM, out IReadOnlyList<DnsResourceRecord> nsec3ParamRecords))
                throw new InvalidOperationException();

            DnsResourceRecord nsec3ParamRecord = nsec3ParamRecords[0];
            DnsNSEC3PARAMRecordData nsec3Param = nsec3ParamRecord.RDATA as DnsNSEC3PARAMRecordData;

            string hashedOwnerName = nsec3Param.ComputeHashedOwnerNameBase32HexString(zone.Name) + (_name.Length > 0 ? "." + _name : "");
            byte[] nextHashedOwnerName = null;

            //find next hashed owner name
            string currentOwnerName = hashedOwnerName;

            while (true)
            {
                AuthZone nextZone = _dnsServer.AuthZoneManager.FindNextSubDomainZone(_name, currentOwnerName);
                if (nextZone is null)
                    break;

                IReadOnlyList<DnsResourceRecord> nextNSec3Records = nextZone.GetRecords(DnsResourceRecordType.NSEC3);
                if (nextNSec3Records.Count > 0)
                {
                    nextHashedOwnerName = DnsNSEC3RecordData.GetHashedOwnerNameFrom(nextNSec3Records[0].Name);
                    break;
                }

                currentOwnerName = nextZone.Name;
            }

            if (nextHashedOwnerName is null)
            {
                //didnt find next NSEC3 record since current must be last; find the first NSEC3 record
                DnsResourceRecord previousNSec3Record = null;

                while (true)
                {
                    AuthZone previousZone = _dnsServer.AuthZoneManager.FindPreviousSubDomainZone(_name, currentOwnerName);
                    if (previousZone is null)
                        break;

                    IReadOnlyList<DnsResourceRecord> previousNSec3Records = previousZone.GetRecords(DnsResourceRecordType.NSEC3);
                    if (previousNSec3Records.Count > 0)
                        previousNSec3Record = previousNSec3Records[0];

                    currentOwnerName = previousZone.Name;
                }

                if (previousNSec3Record is not null)
                    nextHashedOwnerName = DnsNSEC3RecordData.GetHashedOwnerNameFrom(previousNSec3Record.Name);
            }

            if (nextHashedOwnerName is null)
                nextHashedOwnerName = DnsNSEC3RecordData.GetHashedOwnerNameFrom(hashedOwnerName); //only 1 NSEC3 record in zone

            IReadOnlyList<DnsResourceRecord> newNSec3Records = zone.CreateNSec3RRSet(hashedOwnerName, nextHashedOwnerName, ttl, nsec3Param.Iterations, nsec3Param.Salt);

            if (forceGetNewRRSet)
                return newNSec3Records;

            AuthZone nsec3Zone = _dnsServer.AuthZoneManager.GetAuthZone(_name, hashedOwnerName);
            if (nsec3Zone is null)
                return newNSec3Records;

            return nsec3Zone.GetUpdatedNSec3RRSet(newNSec3Records);
        }

        private void RelinkPreviousNSecRRSetFor(DnsResourceRecord currentNSecRecord, uint ttl, bool wasRemoved)
        {
            AuthZone previousNsecZone = _dnsServer.AuthZoneManager.FindPreviousSubDomainZone(_name, currentNSecRecord.Name);
            if (previousNsecZone is null)
                return; //current zone is apex

            IReadOnlyList<DnsResourceRecord> newPreviousNSecRecords;

            if (wasRemoved)
                newPreviousNSecRecords = previousNsecZone.GetUpdatedNSecRRSet((currentNSecRecord.RDATA as DnsNSECRecordData).NextDomainName, ttl);
            else
                newPreviousNSecRecords = previousNsecZone.GetUpdatedNSecRRSet(currentNSecRecord.Name, ttl);

            if (newPreviousNSecRecords.Count > 0)
            {
                if (!previousNsecZone.TrySetRecords(DnsResourceRecordType.NSEC, newPreviousNSecRecords, out IReadOnlyList<DnsResourceRecord> deletedNSecRecords))
                    throw new DnsServerException("Failed to set DNSSEC records. Please try again.");

                List<DnsResourceRecord> addedRecords = new List<DnsResourceRecord>();
                List<DnsResourceRecord> deletedRecords = new List<DnsResourceRecord>();

                addedRecords.AddRange(newPreviousNSecRecords);
                deletedRecords.AddRange(deletedNSecRecords);

                IReadOnlyList<DnsResourceRecord> newRRSigRecords = SignRRSet(newPreviousNSecRecords);
                if (newRRSigRecords.Count > 0)
                {
                    previousNsecZone.AddOrUpdateRRSigRecords(newRRSigRecords, out IReadOnlyList<DnsResourceRecord> deletedRRSigRecords);

                    addedRecords.AddRange(newRRSigRecords);
                    deletedRecords.AddRange(deletedRRSigRecords);
                }

                CommitAndIncrementSerial(deletedRecords, addedRecords);
            }
        }

        private void RelinkPreviousNSec3RRSet(DnsResourceRecord currentNSec3Record, uint ttl, bool wasRemoved)
        {
            DnsNSEC3RecordData currentNSec3 = currentNSec3Record.RDATA as DnsNSEC3RecordData;

            //find the previous NSEC3 and update it
            DnsResourceRecord previousNSec3Record = null;
            AuthZone previousNSec3Zone;
            string currentOwnerName = currentNSec3Record.Name;

            while (true)
            {
                previousNSec3Zone = _dnsServer.AuthZoneManager.FindPreviousSubDomainZone(_name, currentOwnerName);
                if (previousNSec3Zone is null)
                    break;

                IReadOnlyList<DnsResourceRecord> previousNSec3Records = previousNSec3Zone.GetRecords(DnsResourceRecordType.NSEC3);
                if (previousNSec3Records.Count > 0)
                {
                    previousNSec3Record = previousNSec3Records[0];
                    break;
                }

                currentOwnerName = previousNSec3Zone.Name;
            }

            if (previousNSec3Record is null)
            {
                //didnt find previous NSEC3; find the last NSEC3 to update
                if (wasRemoved)
                    currentOwnerName = currentNSec3.NextHashedOwnerName + (_name.Length > 0 ? "." + _name : "");
                else
                    currentOwnerName = currentNSec3Record.Name;

                while (true)
                {
                    AuthZone nextNSec3Zone = _dnsServer.AuthZoneManager.GetAuthZone(_name, currentOwnerName);
                    if (nextNSec3Zone is null)
                        break;

                    IReadOnlyList<DnsResourceRecord> nextNSec3Records = nextNSec3Zone.GetRecords(DnsResourceRecordType.NSEC3);
                    if (nextNSec3Records.Count > 0)
                    {
                        previousNSec3Record = nextNSec3Records[0];
                        previousNSec3Zone = nextNSec3Zone;

                        string nextHashedOwnerNameString = (previousNSec3Record.RDATA as DnsNSEC3RecordData).NextHashedOwnerName + (_name.Length > 0 ? "." + _name : "");
                        if (DnsNSECRecordData.CanonicalComparison(previousNSec3Record.Name, nextHashedOwnerNameString) >= 0)
                            break; //found last NSEC3

                        //jump to next hashed owner
                        currentOwnerName = nextHashedOwnerNameString;
                    }
                    else
                    {
                        currentOwnerName = nextNSec3Zone.Name;
                    }
                }
            }

            if (previousNSec3Record is null)
                throw new InvalidOperationException();

            DnsNSEC3RecordData previousNSec3 = previousNSec3Record.RDATA as DnsNSEC3RecordData;
            DnsNSEC3RecordData newPreviousNSec3;

            if (wasRemoved)
                newPreviousNSec3 = new DnsNSEC3RecordData(DnssecNSEC3HashAlgorithm.SHA1, DnssecNSEC3Flags.None, previousNSec3.Iterations, previousNSec3.Salt, currentNSec3.NextHashedOwnerNameValue, previousNSec3.Types);
            else
                newPreviousNSec3 = new DnsNSEC3RecordData(DnssecNSEC3HashAlgorithm.SHA1, DnssecNSEC3Flags.None, previousNSec3.Iterations, previousNSec3.Salt, DnsNSEC3RecordData.GetHashedOwnerNameFrom(currentNSec3Record.Name), previousNSec3.Types);

            DnsResourceRecord[] newPreviousNSec3Records = new DnsResourceRecord[] { new DnsResourceRecord(previousNSec3Record.Name, DnsResourceRecordType.NSEC3, DnsClass.IN, ttl, newPreviousNSec3) };

            if (!previousNSec3Zone.TrySetRecords(DnsResourceRecordType.NSEC3, newPreviousNSec3Records, out IReadOnlyList<DnsResourceRecord> deletedNSec3Records))
                throw new DnsServerException("Failed to set DNSSEC records. Please try again.");

            List<DnsResourceRecord> addedRecords = new List<DnsResourceRecord>();
            List<DnsResourceRecord> deletedRecords = new List<DnsResourceRecord>();

            addedRecords.AddRange(newPreviousNSec3Records);
            deletedRecords.AddRange(deletedNSec3Records);

            IReadOnlyList<DnsResourceRecord> newRRSigRecords = SignRRSet(newPreviousNSec3Records);
            if (newRRSigRecords.Count > 0)
            {
                previousNSec3Zone.AddOrUpdateRRSigRecords(newRRSigRecords, out IReadOnlyList<DnsResourceRecord> deletedRRSigRecords);

                addedRecords.AddRange(newRRSigRecords);
                deletedRecords.AddRange(deletedRRSigRecords);
            }

            CommitAndIncrementSerial(deletedRecords, addedRecords);
        }

        private uint GetSignatureValidityPeriod()
        {
            //SOA EXPIRE * 2
            return GetZoneSoaExpire() * 2;
        }

        private uint GetPropagationDelay()
        {
            //the max time required to sync zone changes to secondaries if NOTIFY fails to trigger a zone transfer
            DnsSOARecordData soa = _entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecordData;
            return soa.Refresh + soa.Retry;
        }

        private async Task<uint> GetParentSidePropagationDelayAsync(CancellationToken cancellationToken = default)
        {
            uint parentSidePropagationDelay = 24 * 60 * 60;

            try
            {
                string parent = AuthZoneManager.GetParentZone(_name);
                if (parent is null)
                    parent = "";

                DnsDatagram soaResponse = await _dnsServer.DirectQueryAsync(new DnsQuestionRecord(parent, DnsResourceRecordType.SOA, DnsClass.IN), 10000, cancellationToken: cancellationToken);
                if (soaResponse.RCODE == DnsResponseCode.NoError)
                {
                    IReadOnlyList<DnsResourceRecord> records;

                    if (soaResponse.Answer.Count > 0)
                        records = soaResponse.Answer;
                    else if (soaResponse.Authority.Count > 0)
                        records = soaResponse.Authority;
                    else
                        records = null;

                    if (records is not null)
                    {
                        foreach (DnsResourceRecord record in records)
                        {
                            if (record.Type == DnsResourceRecordType.SOA)
                            {
                                DnsSOARecordData parentSoa = record.RDATA as DnsSOARecordData;
                                parentSidePropagationDelay = parentSoa.Refresh + parentSoa.Retry;
                                break;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write(ex);
            }

            return parentSidePropagationDelay;
        }

        private uint GetMaxRRSigTtl()
        {
            uint maxTtl = 0;

            foreach (AuthZone zone in _dnsServer.AuthZoneManager.GetApexZoneWithSubDomainZones(_name))
            {
                if (!zone.Entries.TryGetValue(DnsResourceRecordType.RRSIG, out IReadOnlyList<DnsResourceRecord> rrsigRecords))
                    continue;

                foreach (DnsResourceRecord rr in rrsigRecords)
                {
                    if (rr.OriginalTtlValue > maxTtl)
                        maxTtl = rr.OriginalTtlValue;
                }
            }

            return maxTtl;
        }

        private async Task<uint> GetDSTtlAsync(CancellationToken cancellationToken = default)
        {
            uint dsTtl = 24 * 60 * 60;

            try
            {
                DnsDatagram dsResponse = await _dnsServer.DirectQueryAsync(new DnsQuestionRecord(_name, DnsResourceRecordType.DS, DnsClass.IN), 10000, cancellationToken: cancellationToken);
                if (dsResponse.RCODE == DnsResponseCode.NoError)
                {
                    if (dsResponse.Answer.Count > 0)
                    {
                        //find min TTL
                        dsTtl = 0;

                        foreach (DnsResourceRecord answer in dsResponse.Answer)
                        {
                            if (answer.Type == DnsResourceRecordType.DS)
                            {
                                if ((dsTtl == 0) || (dsTtl > answer.OriginalTtlValue))
                                    dsTtl = answer.OriginalTtlValue;
                            }
                        }
                    }
                    else
                    {
                        dsTtl = 0; //no DS was found
                    }
                }
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write(ex);
            }

            return dsTtl;
        }

        public uint GetDnsKeyTtl()
        {
            if (_entries.TryGetValue(DnsResourceRecordType.DNSKEY, out IReadOnlyList<DnsResourceRecord> dnsKeyRecords))
                return dnsKeyRecords[0].OriginalTtlValue;

            return 24 * 60 * 60;
        }

        public void UpdateDnsKeyTtl(uint dnsKeyTtl)
        {
            if (_dnssecStatus == AuthZoneDnssecStatus.Unsigned)
                throw new DnsServerException("The zone must be signed.");

            lock (_dnssecPrivateKeys)
            {
                foreach (KeyValuePair<ushort, DnssecPrivateKey> privateKeyEntry in _dnssecPrivateKeys)
                {
                    switch (privateKeyEntry.Value.State)
                    {
                        case DnssecPrivateKeyState.Ready:
                        case DnssecPrivateKeyState.Active:
                            break;

                        default:
                            throw new DnsServerException("Cannot update DNSKEY TTL value: one or more private keys have state other than Ready or Active.");
                    }
                }
            }

            if (!_entries.TryGetValue(DnsResourceRecordType.DNSKEY, out IReadOnlyList<DnsResourceRecord> dnsKeyRecords))
                throw new InvalidOperationException();

            DnsResourceRecord[] newDnsKeyRecords = new DnsResourceRecord[dnsKeyRecords.Count];

            for (int i = 0; i < dnsKeyRecords.Count; i++)
            {
                DnsResourceRecord dnsKeyRecord = dnsKeyRecords[i];
                newDnsKeyRecords[i] = new DnsResourceRecord(dnsKeyRecord.Name, DnsResourceRecordType.DNSKEY, DnsClass.IN, dnsKeyTtl, dnsKeyRecord.RDATA);
            }

            List<DnsResourceRecord> addedRecords = new List<DnsResourceRecord>();
            List<DnsResourceRecord> deletedRecords = new List<DnsResourceRecord>();

            if (!TrySetRecords(DnsResourceRecordType.DNSKEY, newDnsKeyRecords, out IReadOnlyList<DnsResourceRecord> deletedDnsKeyRecords))
                throw new DnsServerException("Failed to update DNSKEY TTL. Please try again.");

            addedRecords.AddRange(newDnsKeyRecords);
            deletedRecords.AddRange(deletedDnsKeyRecords);

            IReadOnlyList<DnsResourceRecord> newRRSigRecords = SignRRSet(newDnsKeyRecords);
            if (newRRSigRecords.Count > 0)
            {
                AddOrUpdateRRSigRecords(newRRSigRecords, out IReadOnlyList<DnsResourceRecord> deletedRRSigRecords);

                addedRecords.AddRange(newRRSigRecords);
                deletedRecords.AddRange(deletedRRSigRecords);
            }

            CommitAndIncrementSerial(deletedRecords, addedRecords);
            TriggerNotify();
        }

        #endregion

        #region versioning

        internal override void CommitAndIncrementSerial(IReadOnlyList<DnsResourceRecord> deletedRecords = null, IReadOnlyList<DnsResourceRecord> addedRecords = null)
        {
            if (_internal)
            {
                _lastModified = DateTime.UtcNow;
                return;
            }

            base.CommitAndIncrementSerial(deletedRecords, addedRecords);
        }

        #endregion

        #region public

        public override string GetZoneTypeName()
        {
            return "Primary";
        }

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            if (_dnssecStatus != AuthZoneDnssecStatus.Unsigned)
            {
                switch (type)
                {
                    case DnsResourceRecordType.ANAME:
                    case DnsResourceRecordType.APP:
                        throw new DnsServerException("The record type is not supported by DNSSEC signed primary zones.");

                    default:
                        foreach (DnsResourceRecord record in records)
                        {
                            if (record.GetAuthGenericRecordInfo().Disabled)
                                throw new DnsServerException("Cannot set records: disabling records in a signed zones is not supported.");
                        }

                        break;
                }
            }

            switch (type)
            {
                case DnsResourceRecordType.CNAME:
                case DnsResourceRecordType.DS:
                    throw new InvalidOperationException("Cannot set " + type.ToString() + " record at zone apex.");

                case DnsResourceRecordType.SOA:
                    if ((records.Count != 1) || !records[0].Name.Equals(_name, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("Invalid SOA record.");

                    DnsResourceRecord newSoaRecord = records[0];
                    DnsSOARecordData newSoa = newSoaRecord.RDATA as DnsSOARecordData;

                    if (newSoaRecord.OriginalTtlValue > newSoa.Expire)
                        throw new DnsServerException("Cannot set record: TTL cannot be greater than SOA EXPIRE.");

                    if (newSoa.Retry > newSoa.Refresh)
                        throw new DnsServerException("Cannot set record: SOA RETRY cannot be greater than SOA REFRESH.");

                    if (newSoa.Refresh > newSoa.Expire)
                        throw new DnsServerException("Cannot set record: SOA REFRESH cannot be greater than SOA EXPIRE.");

                    //remove any record info except serial date scheme and comments
                    bool useSoaSerialDateScheme;
                    string comments;
                    {
                        SOARecordInfo recordInfo = newSoaRecord.GetAuthSOARecordInfo();

                        useSoaSerialDateScheme = recordInfo.UseSoaSerialDateScheme;
                        comments = recordInfo.Comments;
                    }

                    newSoaRecord.Tag = null; //remove old record info

                    {
                        SOARecordInfo recordInfo = newSoaRecord.GetAuthSOARecordInfo();

                        recordInfo.UseSoaSerialDateScheme = useSoaSerialDateScheme;
                        recordInfo.Comments = comments;
                        recordInfo.LastModified = DateTime.UtcNow;
                    }

                    uint oldSoaMinimum = GetZoneSoaMinimum();

                    //setting new SOA
                    if (_internal)
                        _entries[DnsResourceRecordType.SOA] = records; //update SOA directly
                    else
                        CommitAndIncrementSerial(null, records);

                    if (oldSoaMinimum != newSoa.Minimum)
                    {
                        switch (_dnssecStatus)
                        {
                            case AuthZoneDnssecStatus.SignedWithNSEC:
                                RefreshNSec();
                                break;

                            case AuthZoneDnssecStatus.SignedWithNSEC3:
                                RefreshNSec3();
                                break;
                        }
                    }

                    TriggerNotify();
                    break;

                case DnsResourceRecordType.DNSKEY:
                case DnsResourceRecordType.RRSIG:
                case DnsResourceRecordType.NSEC:
                case DnsResourceRecordType.NSEC3PARAM:
                case DnsResourceRecordType.NSEC3:
                    throw new InvalidOperationException("Cannot set DNSSEC records.");

                case DnsResourceRecordType.FWD:
                    throw new DnsServerException("The record type is not supported by primary zones.");

                default:
                    if (records[0].OriginalTtlValue > GetZoneSoaExpire())
                        throw new DnsServerException("Cannot set records: TTL cannot be greater than SOA EXPIRE.");

                    if (!TrySetRecords(type, records, out IReadOnlyList<DnsResourceRecord> deletedRecords))
                        throw new DnsServerException("Cannot set records. Please try again.");

                    CommitAndIncrementSerial(deletedRecords, records);

                    if (_dnssecStatus != AuthZoneDnssecStatus.Unsigned)
                        UpdateDnssecRecordsFor(this, type);

                    TriggerNotify();
                    break;
            }
        }

        public override bool AddRecord(DnsResourceRecord record)
        {
            if (_dnssecStatus != AuthZoneDnssecStatus.Unsigned)
            {
                switch (record.Type)
                {
                    case DnsResourceRecordType.ANAME:
                    case DnsResourceRecordType.APP:
                        throw new DnsServerException("The record type is not supported by DNSSEC signed primary zones.");

                    default:
                        if (record.GetAuthGenericRecordInfo().Disabled)
                            throw new DnsServerException("Cannot add record: disabling records in a signed zones is not supported.");

                        break;
                }
            }

            switch (record.Type)
            {
                case DnsResourceRecordType.APP:
                    throw new InvalidOperationException("Cannot add record: use SetRecords() for " + record.Type.ToString() + " record");

                case DnsResourceRecordType.DS:
                    throw new InvalidOperationException("Cannot set DS record at zone apex.");

                case DnsResourceRecordType.DNSKEY:
                case DnsResourceRecordType.RRSIG:
                case DnsResourceRecordType.NSEC:
                case DnsResourceRecordType.NSEC3PARAM:
                case DnsResourceRecordType.NSEC3:
                    throw new InvalidOperationException("Cannot add DNSSEC record.");

                case DnsResourceRecordType.FWD:
                    throw new DnsServerException("The record type is not supported by primary zones.");

                default:
                    if (record.OriginalTtlValue > GetZoneSoaExpire())
                        throw new DnsServerException("Cannot add record: TTL cannot be greater than SOA EXPIRE.");

                    AddRecord(record, out IReadOnlyList<DnsResourceRecord> addedRecords, out IReadOnlyList<DnsResourceRecord> deletedRecords);

                    if (addedRecords.Count > 0)
                    {
                        CommitAndIncrementSerial(deletedRecords, addedRecords);

                        if (_dnssecStatus != AuthZoneDnssecStatus.Unsigned)
                            UpdateDnssecRecordsFor(this, record.Type);

                        TriggerNotify();

                        return true;
                    }

                    return false;
            }
        }

        public override bool DeleteRecords(DnsResourceRecordType type)
        {
            switch (type)
            {
                case DnsResourceRecordType.SOA:
                    throw new InvalidOperationException("Cannot delete SOA record.");

                case DnsResourceRecordType.DNSKEY:
                case DnsResourceRecordType.RRSIG:
                case DnsResourceRecordType.NSEC:
                case DnsResourceRecordType.NSEC3PARAM:
                case DnsResourceRecordType.NSEC3:
                    throw new InvalidOperationException("Cannot delete DNSSEC records.");

                default:
                    if (_entries.TryRemove(type, out IReadOnlyList<DnsResourceRecord> removedRecords))
                    {
                        CommitAndIncrementSerial(removedRecords);

                        if (_dnssecStatus != AuthZoneDnssecStatus.Unsigned)
                            UpdateDnssecRecordsFor(this, type);

                        TriggerNotify();

                        return true;
                    }

                    return false;
            }
        }

        public override bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData rdata)
        {
            switch (type)
            {
                case DnsResourceRecordType.SOA:
                    throw new InvalidOperationException("Cannot delete SOA record.");

                case DnsResourceRecordType.DNSKEY:
                case DnsResourceRecordType.RRSIG:
                case DnsResourceRecordType.NSEC:
                case DnsResourceRecordType.NSEC3PARAM:
                case DnsResourceRecordType.NSEC3:
                    throw new InvalidOperationException("Cannot delete DNSSEC records.");

                default:
                    if (TryDeleteRecord(type, rdata, out DnsResourceRecord deletedRecord))
                    {
                        CommitAndIncrementSerial([deletedRecord]);

                        if (_dnssecStatus != AuthZoneDnssecStatus.Unsigned)
                            UpdateDnssecRecordsFor(this, type);

                        TriggerNotify();

                        return true;
                    }

                    return false;
            }
        }

        public override void UpdateRecord(DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            switch (oldRecord.Type)
            {
                case DnsResourceRecordType.SOA:
                    throw new InvalidOperationException("Cannot update record: use SetRecords() for " + oldRecord.Type.ToString() + " record");

                case DnsResourceRecordType.DNSKEY:
                case DnsResourceRecordType.RRSIG:
                case DnsResourceRecordType.NSEC:
                case DnsResourceRecordType.NSEC3PARAM:
                case DnsResourceRecordType.NSEC3:
                    throw new InvalidOperationException("Cannot update DNSSEC records.");

                default:
                    if (oldRecord.Type != newRecord.Type)
                        throw new InvalidOperationException("Old and new record types do not match.");

                    if ((_dnssecStatus != AuthZoneDnssecStatus.Unsigned) && newRecord.GetAuthGenericRecordInfo().Disabled)
                        throw new DnsServerException("Cannot update record: disabling records in a signed zones is not supported.");

                    if (newRecord.OriginalTtlValue > GetZoneSoaExpire())
                        throw new DnsServerException("Cannot update record: TTL cannot be greater than SOA EXPIRE.");

                    if (!TryDeleteRecord(oldRecord.Type, oldRecord.RDATA, out DnsResourceRecord deletedRecord))
                        throw new DnsServerException("Cannot update record: the record does not exists to be updated.");

                    AddRecord(newRecord, out IReadOnlyList<DnsResourceRecord> addedRecords, out IReadOnlyList<DnsResourceRecord> deletedRecords);

                    List<DnsResourceRecord> allDeletedRecords = new List<DnsResourceRecord>(deletedRecords.Count + 1);
                    allDeletedRecords.Add(deletedRecord);
                    allDeletedRecords.AddRange(deletedRecords);

                    CommitAndIncrementSerial(allDeletedRecords, addedRecords);

                    if (_dnssecStatus != AuthZoneDnssecStatus.Unsigned)
                        UpdateDnssecRecordsFor(this, oldRecord.Type);

                    TriggerNotify();
                    break;
            }
        }

        #endregion

        #region properties

        public override bool Disabled
        {
            get { return base.Disabled; }
            set
            {
                if (base.Disabled == value)
                    return;

                base.Disabled = value; //set value early to be able to use it for notify

                if (value)
                    DisableNotifyTimer();
                else
                    TriggerNotify();
            }
        }

        public override AuthZoneTransfer ZoneTransfer
        {
            get { return base.ZoneTransfer; }
            set
            {
                if (_internal)
                    throw new InvalidOperationException();

                base.ZoneTransfer = value;
            }
        }

        public override AuthZoneNotify Notify
        {
            get { return base.Notify; }
            set
            {
                if (_internal)
                    throw new InvalidOperationException();

                switch (value)
                {
                    case AuthZoneNotify.SeparateNameServersForCatalogAndMemberZones:
                        throw new ArgumentException("The Notify option is invalid for " + GetZoneTypeName() + " zones: " + value.ToString(), nameof(Notify));
                }

                base.Notify = value;
            }
        }

        public override AuthZoneUpdate Update
        {
            get { return base.Update; }
            set
            {
                if (_internal)
                    throw new InvalidOperationException();

                base.Update = value;
            }
        }

        public bool Internal
        { get { return _internal; } }

        public IReadOnlyCollection<DnssecPrivateKey> DnssecPrivateKeys
        {
            get
            {
                if (_dnssecPrivateKeys is null)
                    return null;

                lock (_dnssecPrivateKeys)
                {
                    return _dnssecPrivateKeys.Values;
                }
            }
        }

        #endregion
    }
}
