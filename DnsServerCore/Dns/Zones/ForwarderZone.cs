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
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    class ForwarderZone : ApexZone
    {
        #region constructor

        public ForwarderZone(DnsServer dnsServer, AuthZoneInfo zoneInfo)
            : base(dnsServer, zoneInfo)
        {
            InitNotify();
            InitRecordExpiry();
        }

        public ForwarderZone(DnsServer dnsServer, string name)
            : base(dnsServer, name)
        {
            InitZone();
            InitNotify();
            InitRecordExpiry();
        }

        public ForwarderZone(DnsServer dnsServer, string name, DnsTransportProtocol forwarderProtocol, string forwarder, bool dnssecValidation, DnsForwarderRecordProxyType proxyType, string proxyAddress, ushort proxyPort, string proxyUsername, string proxyPassword, string fwdRecordComments)
            : base(dnsServer, name)
        {
            DnsResourceRecord fwdRecord = new DnsResourceRecord(name, DnsResourceRecordType.FWD, DnsClass.IN, 0, new DnsForwarderRecordData(forwarderProtocol, forwarder, dnssecValidation, proxyType, proxyAddress, proxyPort, proxyUsername, proxyPassword, 0));

            if (!string.IsNullOrEmpty(fwdRecordComments))
                fwdRecord.GetAuthGenericRecordInfo().Comments = fwdRecordComments;

            fwdRecord.GetAuthGenericRecordInfo().LastModified = DateTime.UtcNow;

            _entries[DnsResourceRecordType.FWD] = [fwdRecord];

            InitZone();
            InitNotify();
            InitRecordExpiry();
        }

        #endregion

        #region internal

        internal virtual void InitZone()
        {
            //init forwarder zone with dummy SOA record
            DnsSOARecordData soa = new DnsSOARecordData(_dnsServer.ServerDomain, "invalid", 1, 900, 300, 604800, 900);
            DnsResourceRecord soaRecord = new DnsResourceRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN, 0, soa);
            soaRecord.GetAuthGenericRecordInfo().LastModified = DateTime.UtcNow;

            _entries[DnsResourceRecordType.SOA] = [soaRecord];
        }

        #endregion

        #region public

        public override string GetZoneTypeName()
        {
            return "Conditional Forwarder";
        }

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            switch (type)
            {
                case DnsResourceRecordType.CNAME:
                    throw new InvalidOperationException("Cannot set CNAME record at zone apex.");

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

                    {
                        //reset fixed record values
                        DnsSOARecordData modifiedSoa = new DnsSOARecordData(newSoa.PrimaryNameServer, "invalid", newSoa.Serial, newSoa.Refresh, newSoa.Retry, newSoa.Expire, newSoa.Minimum);
                        newSoaRecord = new DnsResourceRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN, 0, modifiedSoa) { Tag = newSoaRecord.Tag };
                        records = [newSoaRecord];
                    }

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

                    //setting new SOA
                    CommitAndIncrementSerial(null, records);

                    TriggerNotify();
                    break;

                case DnsResourceRecordType.DS:
                case DnsResourceRecordType.DNSKEY:
                case DnsResourceRecordType.RRSIG:
                case DnsResourceRecordType.NSEC:
                case DnsResourceRecordType.NSEC3PARAM:
                case DnsResourceRecordType.NSEC3:
                    throw new InvalidOperationException("Cannot set DNSSEC records.");

                default:
                    if (records[0].OriginalTtlValue > GetZoneSoaExpire())
                        throw new DnsServerException("Cannot set records: TTL cannot be greater than SOA EXPIRE.");

                    if (!TrySetRecords(type, records, out IReadOnlyList<DnsResourceRecord> deletedRecords))
                        throw new DnsServerException("Cannot set records. Please try again.");

                    CommitAndIncrementSerial(deletedRecords, records);

                    TriggerNotify();
                    break;
            }
        }

        public override bool AddRecord(DnsResourceRecord record)
        {
            switch (record.Type)
            {
                case DnsResourceRecordType.DS:
                case DnsResourceRecordType.DNSKEY:
                case DnsResourceRecordType.RRSIG:
                case DnsResourceRecordType.NSEC:
                case DnsResourceRecordType.NSEC3PARAM:
                case DnsResourceRecordType.NSEC3:
                    throw new InvalidOperationException("Cannot set DNSSEC records.");

                default:
                    if (record.OriginalTtlValue > GetZoneSoaExpire())
                        throw new DnsServerException("Cannot add record: TTL cannot be greater than SOA EXPIRE.");

                    AddRecord(record, out IReadOnlyList<DnsResourceRecord> addedRecords, out IReadOnlyList<DnsResourceRecord> deletedRecords);

                    if (addedRecords.Count > 0)
                    {
                        CommitAndIncrementSerial(deletedRecords, addedRecords);

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

                default:
                    if (_entries.TryRemove(type, out IReadOnlyList<DnsResourceRecord> removedRecords))
                    {
                        CommitAndIncrementSerial(removedRecords);

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

                default:
                    if (TryDeleteRecord(type, rdata, out DnsResourceRecord deletedRecord))
                    {
                        CommitAndIncrementSerial([deletedRecord]);

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

                default:
                    if (oldRecord.Type != newRecord.Type)
                        throw new InvalidOperationException("Old and new record types do not match.");

                    if (newRecord.OriginalTtlValue > GetZoneSoaExpire())
                        throw new DnsServerException("Cannot update record: TTL cannot be greater than SOA EXPIRE.");

                    if (!TryDeleteRecord(oldRecord.Type, oldRecord.RDATA, out DnsResourceRecord deletedRecord))
                        throw new DnsServerException("Cannot update record: the record does not exists to be updated.");

                    AddRecord(newRecord, out IReadOnlyList<DnsResourceRecord> addedRecords, out IReadOnlyList<DnsResourceRecord> deletedRecords);

                    List<DnsResourceRecord> allDeletedRecords = new List<DnsResourceRecord>(deletedRecords.Count + 1);
                    allDeletedRecords.Add(deletedRecord);
                    allDeletedRecords.AddRange(deletedRecords);

                    CommitAndIncrementSerial(allDeletedRecords, addedRecords);

                    TriggerNotify();
                    break;
            }
        }

        public override IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type, bool dnssecOk)
        {
            if (this is CatalogZone)
                return base.QueryRecords(type, dnssecOk);

            if (type == DnsResourceRecordType.SOA)
                return []; //forwarder zone is not authoritative and contains dummy SOA record

            return base.QueryRecords(type, dnssecOk);
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

        public override AuthZoneQueryAccess QueryAccess
        {
            get { return base.QueryAccess; }
            set
            {
                switch (value)
                {
                    case AuthZoneQueryAccess.AllowOnlyZoneNameServers:
                    case AuthZoneQueryAccess.AllowZoneNameServersAndUseSpecifiedNetworkACL:
                        throw new ArgumentException("The Query Access option is invalid for " + GetZoneTypeName() + " zones: " + value.ToString(), nameof(QueryAccess));
                }

                base.QueryAccess = value;
            }
        }

        public override AuthZoneTransfer ZoneTransfer
        {
            get { return base.ZoneTransfer; }
            set
            {
                switch (value)
                {
                    case AuthZoneTransfer.AllowOnlyZoneNameServers:
                    case AuthZoneTransfer.AllowZoneNameServersAndUseSpecifiedNetworkACL:
                        throw new ArgumentException("The Zone Transfer option is invalid for " + GetZoneTypeName() + " zones: " + value.ToString(), nameof(ZoneTransfer));
                }

                base.ZoneTransfer = value;
            }
        }

        public override AuthZoneNotify Notify
        {
            get { return base.Notify; }
            set
            {
                switch (value)
                {
                    case AuthZoneNotify.ZoneNameServers:
                    case AuthZoneNotify.BothZoneAndSpecifiedNameServers:
                        throw new ArgumentException("The Notify option is invalid for " + GetZoneTypeName() + " zones: " + value.ToString(), nameof(Notify));

                    case AuthZoneNotify.SeparateNameServersForCatalogAndMemberZones:
                        if (this is CatalogZone)
                            break;

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
                switch (value)
                {
                    case AuthZoneUpdate.AllowOnlyZoneNameServers:
                    case AuthZoneUpdate.AllowZoneNameServersAndUseSpecifiedNetworkACL:
                        throw new ArgumentException("The Dynamic Updates option is invalid for " + GetZoneTypeName() + " zones: " + value.ToString(), nameof(Update));
                }

                base.Update = value;
            }
        }

        #endregion
    }
}
