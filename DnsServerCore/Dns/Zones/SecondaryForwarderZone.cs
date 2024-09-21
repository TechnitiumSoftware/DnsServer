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
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    class SecondaryForwarderZone : SecondaryZone
    {
        #region constructor

        public SecondaryForwarderZone(DnsServer dnsServer, AuthZoneInfo zoneInfo)
            : base(dnsServer, zoneInfo)
        { }

        public SecondaryForwarderZone(DnsServer dnsServer, string name, IReadOnlyList<NameServerAddress> primaryNameServerAddresses, DnsTransportProtocol primaryZoneTransferProtocol = DnsTransportProtocol.Tcp, string primaryZoneTransferTsigKeyName = null)
            : base(dnsServer, name, primaryNameServerAddresses, primaryZoneTransferProtocol, primaryZoneTransferTsigKeyName, false)
        {
            InitZone();
        }

        #endregion

        #region protected

        protected virtual void InitZone()
        {
            //init secondary forwarder zone with dummy SOA record
            DnsSOARecordData soa = new DnsSOARecordData(_dnsServer.ServerDomain, "invalid", 0, 900, 300, 604800, 900);
            DnsResourceRecord soaRecord = new DnsResourceRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN, 0, soa);
            soaRecord.GetAuthGenericRecordInfo().LastModified = DateTime.UtcNow;

            _entries[DnsResourceRecordType.SOA] = [soaRecord];
        }

        protected override Task FinalizeZoneTransferAsync()
        {
            //secondary forwarder does not maintain zone history; no need to call base method
            return Task.CompletedTask;
        }

        protected override Task FinalizeIncrementalZoneTransferAsync(IReadOnlyList<DnsResourceRecord> historyRecords)
        {
            //secondary forwarder does not maintain zone history; no need to call base method
            return Task.CompletedTask;
        }

        #endregion

        #region public

        public override string GetZoneTypeName()
        {
            return "Secondary Forwarder";
        }

        public override IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type, bool dnssecOk)
        {
            if (type == DnsResourceRecordType.SOA)
                return []; //secondary forwarder zone is not authoritative and contains dummy SOA record

            return base.QueryRecords(type, dnssecOk);
        }

        #endregion

        #region properties

        public override bool OverrideCatalogZoneTransfer
        {
            get { throw new InvalidOperationException(); }
            set { throw new InvalidOperationException(); }
        }

        public override bool OverrideCatalogPrimaryNameServers
        {
            get { throw new InvalidOperationException(); }
            set { throw new InvalidOperationException(); }
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
                        throw new ArgumentException("The Query Access option is invalid for Secondary Conditional Forwarder zones: " + value.ToString(), nameof(QueryAccess));
                }

                base.QueryAccess = value;
            }
        }

        public override AuthZoneTransfer ZoneTransfer
        {
            get { return base.ZoneTransfer; }
            set { throw new InvalidOperationException(); }
        }

        public override AuthZoneNotify Notify
        {
            get { return base.Notify; }
            set { throw new InvalidOperationException(); }
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
                        throw new ArgumentException("The Dynamic Updates option is invalid for Secondary Conditional Forwarder zones: " + value.ToString(), nameof(Update));
                }

                base.Update = value;
            }
        }

        public override IReadOnlyList<NameServerAddress> PrimaryNameServerAddresses
        {
            get { return base.PrimaryNameServerAddresses; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    throw new ArgumentException("At least one primary name server address must be specified for " + GetZoneTypeName() + " zone.", nameof(PrimaryNameServerAddresses));

                base.PrimaryNameServerAddresses = value;
            }
        }

        public override bool ValidateZone
        {
            get { return base.ValidateZone; }
            set { throw new InvalidOperationException(); }
        }

        #endregion
    }
}
