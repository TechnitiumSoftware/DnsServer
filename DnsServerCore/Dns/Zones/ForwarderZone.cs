/*
Technitium DNS Server
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

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

        public ForwarderZone(AuthZoneInfo zoneInfo)
            : base(zoneInfo)
        { }

        public ForwarderZone(string name)
            : base(name)
        {
            _zoneTransfer = AuthZoneTransfer.Deny;
            _notify = AuthZoneNotify.None;
            _update = AuthZoneUpdate.Deny;
        }

        public ForwarderZone(string name, DnsTransportProtocol forwarderProtocol, string forwarder, bool dnssecValidation, DnsForwarderRecordProxyType proxyType, string proxyAddress, ushort proxyPort, string proxyUsername, string proxyPassword, string fwdRecordComments)
            : base(name)
        {
            _zoneTransfer = AuthZoneTransfer.Deny;
            _notify = AuthZoneNotify.None;
            _update = AuthZoneUpdate.Deny;

            DnsResourceRecord fwdRecord = new DnsResourceRecord(name, DnsResourceRecordType.FWD, DnsClass.IN, 0, new DnsForwarderRecordData(forwarderProtocol, forwarder, dnssecValidation, proxyType, proxyAddress, proxyPort, proxyUsername, proxyPassword));

            if (!string.IsNullOrEmpty(fwdRecordComments))
                fwdRecord.GetAuthGenericRecordInfo().Comments = fwdRecordComments;

            _entries[DnsResourceRecordType.FWD] = new DnsResourceRecord[] { fwdRecord };
        }

        #endregion

        #region internal

        internal void UpdateLastModified()
        {
            _lastModified = DateTime.UtcNow;
        }

        #endregion

        #region public

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            switch (type)
            {
                case DnsResourceRecordType.CNAME:
                    throw new InvalidOperationException("Cannot set CNAME record at zone apex.");

                case DnsResourceRecordType.SOA:
                case DnsResourceRecordType.DS:
                    throw new DnsServerException("The record type is not supported by forwarder zones.");

                default:
                    base.SetRecords(type, records);
                    UpdateLastModified();
                    break;
            }
        }

        public override void AddRecord(DnsResourceRecord record)
        {
            switch (record.Type)
            {
                case DnsResourceRecordType.DS:
                    throw new DnsServerException("The record type is not supported by forwarder zones.");

                default:
                    base.AddRecord(record);
                    UpdateLastModified();
                    break;
            }
        }

        public override bool DeleteRecords(DnsResourceRecordType type)
        {
            if (base.DeleteRecords(type))
            {
                UpdateLastModified();
                return true;
            }

            return false;
        }

        public override bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData rdata)
        {
            if (base.DeleteRecord(type, rdata))
            {
                UpdateLastModified();
                return true;
            }

            return false;
        }

        public override void UpdateRecord(DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            base.UpdateRecord(oldRecord, newRecord);
            UpdateLastModified();
        }

        #endregion

        #region properties

        public override AuthZoneTransfer ZoneTransfer
        {
            get { return _zoneTransfer; }
            set { throw new InvalidOperationException(); }
        }

        public override AuthZoneNotify Notify
        {
            get { return _notify; }
            set { throw new InvalidOperationException(); }
        }

        public override AuthZoneUpdate Update
        {
            get { return _update; }
            set
            {
                switch (value)
                {
                    case AuthZoneUpdate.AllowOnlyZoneNameServers:
                    case AuthZoneUpdate.AllowBothZoneNameServersAndSpecifiedIpAddresses:
                        throw new ArgumentException("The Dynamic Updates option is invalid for Conditional Forwarder zones: " + value.ToString(), nameof(Update));
                }

                _update = value;
            }
        }

        #endregion
    }
}
