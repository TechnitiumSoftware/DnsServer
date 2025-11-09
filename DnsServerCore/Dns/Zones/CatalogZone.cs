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

using DnsServerCore.Dns.ResourceRecords;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    class CatalogZone : ForwarderZone
    {
        #region variables

        readonly Dictionary<string, string> _membersIndex = new Dictionary<string, string>();
        readonly ReaderWriterLockSlim _membersIndexLock = new ReaderWriterLockSlim();

        #endregion

        #region constructor

        public CatalogZone(DnsServer dnsServer, AuthZoneInfo zoneInfo)
            : base(dnsServer, zoneInfo)
        { }

        public CatalogZone(DnsServer dnsServer, string name)
            : base(dnsServer, name)
        { }

        #endregion

        #region IDisposable

        protected override void Dispose(bool disposing)
        {
            try
            {
                _membersIndexLock.Dispose();
            }
            finally
            {
                base.Dispose(disposing);
            }
        }

        #endregion

        #region internal

        internal override void InitZone()
        {
            //init catalog zone with dummy SOA and NS records
            DnsSOARecordData soa = new DnsSOARecordData("invalid", "invalid", 1, 300, 60, 604800, 900);
            DnsResourceRecord soaRecord = new DnsResourceRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN, 0, soa);
            soaRecord.GetAuthGenericRecordInfo().LastModified = DateTime.UtcNow;

            _entries[DnsResourceRecordType.SOA] = [soaRecord];
            _entries[DnsResourceRecordType.NS] = [new DnsResourceRecord(_name, DnsResourceRecordType.NS, DnsClass.IN, 0, new DnsNSRecordData("invalid"))];
        }

        internal void InitZoneProperties()
        {
            //set catalog zone version record
            _dnsServer.AuthZoneManager.SetRecord(_name, new DnsResourceRecord("version." + _name, DnsResourceRecordType.TXT, DnsClass.IN, 0, new DnsTXTRecordData("2")));

            //init catalog global properties
            QueryAccess = AuthZoneQueryAccess.Allow;
            ZoneTransfer = AuthZoneTransfer.Deny;
        }

        internal void BuildMembersIndex()
        {
            foreach (KeyValuePair<string, string> memberEntry in EnumerateCatalogMemberZones(_dnsServer))
                _membersIndex.TryAdd(memberEntry.Key.ToLowerInvariant(), memberEntry.Value);
        }

        #endregion

        #region catalog

        public void AddMemberZone(string memberZoneName, AuthZoneType zoneType)
        {
            memberZoneName = memberZoneName.ToLowerInvariant();

            _membersIndexLock.EnterWriteLock();
            try
            {
                if (_membersIndex.TryGetValue(memberZoneName, out _))
                {
                    if (_membersIndex.Remove(memberZoneName, out string removedMemberZoneDomain))
                    {
                        foreach (DnsResourceRecord record in _dnsServer.AuthZoneManager.EnumerateAllRecords(_name, removedMemberZoneDomain, true))
                            _dnsServer.AuthZoneManager.DeleteRecord(_name, record);
                    }
                }

                string memberZoneDomain = GetDomainWithLabel("zones." + _name);
                DateTime utcNow = DateTime.UtcNow;

                DnsResourceRecord ptrRecord = new DnsResourceRecord(memberZoneDomain, DnsResourceRecordType.PTR, DnsClass.IN, 0, new DnsPTRRecordData(memberZoneName));
                ptrRecord.GetAuthGenericRecordInfo().LastModified = utcNow;

                DnsResourceRecord txtRecord = new DnsResourceRecord("zone-type.ext." + memberZoneDomain, DnsResourceRecordType.TXT, DnsClass.IN, 0, new DnsTXTRecordData(zoneType.ToString().ToLowerInvariant()));
                txtRecord.GetAuthGenericRecordInfo().LastModified = utcNow;

                _dnsServer.AuthZoneManager.AddRecord(_name, ptrRecord);
                _dnsServer.AuthZoneManager.AddRecord(_name, txtRecord);

                _membersIndex[memberZoneName] = memberZoneDomain;
            }
            finally
            {
                _membersIndexLock.ExitWriteLock();
            }
        }

        public bool RemoveMemberZone(string memberZoneName)
        {
            memberZoneName = memberZoneName.ToLowerInvariant();

            _membersIndexLock.EnterWriteLock();
            try
            {
                if (_membersIndex.Remove(memberZoneName, out string removedMemberZoneDomain))
                {
                    foreach (DnsResourceRecord record in _dnsServer.AuthZoneManager.EnumerateAllRecords(_name, removedMemberZoneDomain, true))
                        _dnsServer.AuthZoneManager.DeleteRecord(_name, record);

                    return true;
                }

                return false;
            }
            finally
            {
                _membersIndexLock.ExitWriteLock();
            }
        }

        public void ChangeMemberZoneOwnership(string memberZoneName, string newCatalogZoneName)
        {
            string memberZoneDomain = GetMemberZoneDomain(memberZoneName);
            string domain = "coo." + memberZoneDomain;

            DateTime utcNow = DateTime.UtcNow;
            uint soaExpiry = GetZoneSoaExpire();

            //add COO record with expiry
            DnsResourceRecord cooRecord = new DnsResourceRecord(domain, DnsResourceRecordType.PTR, DnsClass.IN, 0, new DnsPTRRecordData(newCatalogZoneName));
            GenericRecordInfo cooRecordInfo = cooRecord.GetAuthGenericRecordInfo();
            cooRecordInfo.LastModified = utcNow;
            cooRecordInfo.ExpiryTtl = soaExpiry;

            _dnsServer.AuthZoneManager.SetRecord(_name, cooRecord);

            //set expiry for other member zone records
            foreach (DnsResourceRecord record in _dnsServer.AuthZoneManager.EnumerateAllRecords(_name, memberZoneDomain, true))
            {
                GenericRecordInfo recordInfo = record.GetAuthGenericRecordInfo();
                recordInfo.LastModified = utcNow;
                recordInfo.ExpiryTtl = soaExpiry;
            }
        }

        public IReadOnlyCollection<string> GetAllMemberZoneNames()
        {
            _membersIndexLock.EnterReadLock();
            try
            {
                return _membersIndex.Keys.ToArray();
            }
            finally
            {
                _membersIndexLock.ExitReadLock();
            }
        }

        public void SetAllowQueryProperty(IReadOnlyCollection<NetworkAccessControl> acl = null, string memberZoneName = null)
        {
            string domain = "allow-query.ext." + GetMemberZoneDomain(memberZoneName);

            if (acl is null)
            {
                _dnsServer.AuthZoneManager.DeleteRecords(_name, domain, DnsResourceRecordType.APL);
            }
            else
            {
                DnsResourceRecord record = new DnsResourceRecord(domain, DnsResourceRecordType.APL, DnsClass.IN, 0, NetworkAccessControl.ConvertToAPLRecordData(acl));
                record.GetAuthGenericRecordInfo().LastModified = DateTime.UtcNow;

                _dnsServer.AuthZoneManager.SetRecord(_name, record);
            }
        }

        public void SetAllowTransferProperty(IReadOnlyCollection<NetworkAccessControl> acl = null, string memberZoneName = null)
        {
            string domain = "allow-transfer.ext." + GetMemberZoneDomain(memberZoneName);

            if (acl is null)
            {
                _dnsServer.AuthZoneManager.DeleteRecords(_name, domain, DnsResourceRecordType.APL);
            }
            else
            {
                DnsResourceRecord record = new DnsResourceRecord(domain, DnsResourceRecordType.APL, DnsClass.IN, 0, NetworkAccessControl.ConvertToAPLRecordData(acl));
                record.GetAuthGenericRecordInfo().LastModified = DateTime.UtcNow;

                _dnsServer.AuthZoneManager.SetRecord(_name, record);
            }
        }

        public void SetZoneTransferTsigKeyNamesProperty(IReadOnlySet<string> tsigKeyNames = null, string memberZoneName = null)
        {
            string domain = "transfer-tsig-key-names.ext." + GetMemberZoneDomain(memberZoneName);

            if (tsigKeyNames is null)
            {
                _dnsServer.AuthZoneManager.DeleteRecords(_name, domain, DnsResourceRecordType.PTR);
            }
            else
            {
                DnsResourceRecord[] records = new DnsResourceRecord[tsigKeyNames.Count];
                int i = 0;

                foreach (string entry in tsigKeyNames)
                {
                    DnsResourceRecord record = new DnsResourceRecord(domain, DnsResourceRecordType.PTR, DnsClass.IN, 0, new DnsPTRRecordData(entry));
                    record.GetAuthGenericRecordInfo().LastModified = DateTime.UtcNow;

                    records[i++] = record;
                }

                _dnsServer.AuthZoneManager.SetRecords(_name, records);
            }
        }

        public void SetPrimaryAddressesProperty(IReadOnlyList<NameServerAddress> primaryServerAddresses = null, string memberZoneName = null)
        {
            string domain = "primary-addresses.ext." + GetMemberZoneDomain(memberZoneName);

            if (primaryServerAddresses is null)
            {
                _dnsServer.AuthZoneManager.DeleteRecords(_name, domain, DnsResourceRecordType.TXT);
            }
            else
            {
                IReadOnlyList<string> charStrings = primaryServerAddresses.Convert(delegate (NameServerAddress nameServer)
                {
                    return nameServer.ToString();
                });

                DnsResourceRecord record = new DnsResourceRecord(domain, DnsResourceRecordType.TXT, DnsClass.IN, 0, new DnsTXTRecordData(charStrings));
                record.GetAuthGenericRecordInfo().LastModified = DateTime.UtcNow;

                _dnsServer.AuthZoneManager.SetRecord(_name, record);
            }
        }

        private string GetMemberZoneDomain(string memberZoneName = null)
        {
            if (memberZoneName is null)
            {
                return _name;
            }
            else
            {
                memberZoneName = memberZoneName.ToLowerInvariant();

                _membersIndexLock.EnterReadLock();
                try
                {
                    if (!_membersIndex.TryGetValue(memberZoneName, out string memberZoneDomain))
                        throw new DnsServerException("Failed to find '" + memberZoneName + "' member zone entry in '" + ToString() + "' Catalog zone: member zone does not exists.");

                    return memberZoneDomain;
                }
                finally
                {
                    _membersIndexLock.ExitReadLock();
                }
            }
        }

        private string GetDomainWithLabel(string domain)
        {
            Span<byte> buffer = stackalloc byte[8];
            int i = 0;

            do
            {
                RandomNumberGenerator.Fill(buffer);
                string label = Base32.ToBase32HexString(buffer, true).ToLowerInvariant();
                string domainWithLabel = label + "." + domain;

                if (_dnsServer.AuthZoneManager.NameExists(_name, domainWithLabel))
                    continue;

                return domainWithLabel;
            }
            while (++i < 10);

            throw new DnsServerException("Failed to generate unique label for the given domain name '" + domain + "'. Please try again.");
        }

        #endregion

        #region public

        public override string GetZoneTypeName()
        {
            return "Catalog";
        }

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            switch (type)
            {
                case DnsResourceRecordType.SOA:
                    if ((records.Count != 1) || !records[0].Name.Equals(_name, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("Invalid SOA record.");

                    DnsResourceRecord newSoaRecord = records[0];
                    DnsSOARecordData newSoa = newSoaRecord.RDATA as DnsSOARecordData;

                    //reset fixed record values
                    DnsSOARecordData modifiedSoa = new DnsSOARecordData("invalid", "invalid", newSoa.Serial, newSoa.Refresh, newSoa.Retry, newSoa.Expire, newSoa.Minimum);
                    DnsResourceRecord modifiedSoaRecord = new DnsResourceRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN, 0, modifiedSoa) { Tag = newSoaRecord.Tag };

                    base.SetRecords(type, [modifiedSoaRecord]);
                    break;

                default:
                    throw new InvalidOperationException("Cannot set records in Catalog zone.");
            }

        }

        public override bool AddRecord(DnsResourceRecord record)
        {
            throw new InvalidOperationException("Cannot add record in Catalog zone.");
        }

        public override bool DeleteRecords(DnsResourceRecordType type)
        {
            throw new InvalidOperationException("Cannot delete record in Catalog zone.");
        }

        public override bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData record)
        {
            throw new InvalidOperationException("Cannot delete records in Catalog zone.");
        }

        public override void UpdateRecord(DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            throw new InvalidOperationException("Cannot update record in Catalog zone.");
        }

        public override IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type, bool dnssecOk)
        {
            if (type == DnsResourceRecordType.SOA)
                return base.QueryRecords(type, dnssecOk); //allow SOA for zone transfer to work with bind

            return []; //catalog zone is not queriable
        }

        #endregion

        #region properties

        public override string CatalogZoneName
        {
            get { return base.CatalogZoneName; }
            set { throw new InvalidOperationException(); }
        }

        public override bool OverrideCatalogQueryAccess
        {
            get { return base.OverrideCatalogQueryAccess; }
            set { throw new InvalidOperationException(); }
        }

        public override bool OverrideCatalogZoneTransfer
        {
            get { return base.OverrideCatalogZoneTransfer; }
            set { throw new InvalidOperationException(); }
        }

        public override bool OverrideCatalogNotify
        {
            get { return base.OverrideCatalogNotify; }
            set { throw new InvalidOperationException(); }
        }

        public override AuthZoneUpdate Update
        {
            get { return base.Update; }
            set { throw new InvalidOperationException(); }
        }

        #endregion
    }
}
