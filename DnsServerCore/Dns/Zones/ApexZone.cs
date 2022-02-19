/*
Technitium DNS Server
Copyright (C) 2022  Shreyas Zare (shreyas@technitium.com)

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
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    public enum AuthZoneTransfer : byte
    {
        Deny = 0,
        Allow = 1,
        AllowOnlyZoneNameServers = 2,
        AllowOnlySpecifiedNameServers = 3
    }

    public enum AuthZoneNotify : byte
    {
        None = 0,
        ZoneNameServers = 1,
        SpecifiedNameServers = 2
    }

    abstract class ApexZone : AuthZone
    {
        #region variables

        protected AuthZoneTransfer _zoneTransfer;
        protected IReadOnlyCollection<IPAddress> _zoneTransferNameServers;
        protected AuthZoneNotify _notify;
        protected IReadOnlyCollection<IPAddress> _notifyNameServers;
        protected AuthZoneDnssecStatus _dnssecStatus;

        #endregion

        #region constructor

        protected ApexZone(AuthZoneInfo zoneInfo)
            : base(zoneInfo)
        {
            _zoneTransfer = zoneInfo.ZoneTransfer;
            _zoneTransferNameServers = zoneInfo.ZoneTransferNameServers;
            _notify = zoneInfo.Notify;
            _notifyNameServers = zoneInfo.NotifyNameServers;
        }

        protected ApexZone(string name)
            : base(name)
        { }

        #endregion

        #region protected

        protected void CleanupHistory(List<DnsResourceRecord> history)
        {
            DnsSOARecord soa = _entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecord;
            DateTime expiry = DateTime.UtcNow.AddSeconds(-soa.Expire);
            int index = 0;

            while (index < history.Count)
            {
                //check difference sequence
                if (history[index].GetDeletedOn() > expiry)
                    break; //found record to keep

                //skip to next difference sequence
                index++;
                int soaCount = 1;

                while (index < history.Count)
                {
                    if (history[index].Type == DnsResourceRecordType.SOA)
                    {
                        soaCount++;

                        if (soaCount == 3)
                            break;
                    }

                    index++;
                }
            }

            if (index == history.Count)
            {
                //delete entire history
                history.Clear();
                return;
            }

            //remove expired records
            history.RemoveRange(0, index);
        }

        #endregion

        #region private

        private static async Task ResolveNameServerAddressesAsync(DnsServer dnsServer, string nsDomain, int port, DnsTransportProtocol protocol, List<NameServerAddress> outNameServers)
        {
            try
            {
                DnsDatagram response = await dnsServer.DirectQueryAsync(new DnsQuestionRecord(nsDomain, DnsResourceRecordType.A, DnsClass.IN));
                if (response.Answer.Count > 0)
                {
                    IReadOnlyList<IPAddress> addresses = DnsClient.ParseResponseA(response);
                    foreach (IPAddress address in addresses)
                        outNameServers.Add(new NameServerAddress(nsDomain, new IPEndPoint(address, port), protocol));
                }
            }
            catch
            { }

            if (dnsServer.PreferIPv6)
            {
                try
                {
                    DnsDatagram response = await dnsServer.DirectQueryAsync(new DnsQuestionRecord(nsDomain, DnsResourceRecordType.AAAA, DnsClass.IN));
                    if (response.Answer.Count > 0)
                    {
                        IReadOnlyList<IPAddress> addresses = DnsClient.ParseResponseAAAA(response);
                        foreach (IPAddress address in addresses)
                            outNameServers.Add(new NameServerAddress(nsDomain, new IPEndPoint(address, port), protocol));
                    }
                }
                catch
                { }
            }
        }

        private static Task ResolveNameServerAddressesAsync(DnsServer dnsServer, DnsResourceRecord nsRecord, List<NameServerAddress> outNameServers)
        {
            switch (nsRecord.Type)
            {
                case DnsResourceRecordType.NS:
                    {
                        string nsDomain = (nsRecord.RDATA as DnsNSRecord).NameServer;

                        IReadOnlyList<DnsResourceRecord> glueRecords = nsRecord.GetGlueRecords();
                        if (glueRecords.Count > 0)
                        {
                            foreach (DnsResourceRecord glueRecord in glueRecords)
                            {
                                switch (glueRecord.Type)
                                {
                                    case DnsResourceRecordType.A:
                                        outNameServers.Add(new NameServerAddress(nsDomain, (glueRecord.RDATA as DnsARecord).Address));
                                        break;

                                    case DnsResourceRecordType.AAAA:
                                        if (dnsServer.PreferIPv6)
                                            outNameServers.Add(new NameServerAddress(nsDomain, (glueRecord.RDATA as DnsAAAARecord).Address));

                                        break;
                                }
                            }

                            return Task.CompletedTask;
                        }
                        else
                        {
                            return ResolveNameServerAddressesAsync(dnsServer, nsDomain, 53, DnsTransportProtocol.Udp, outNameServers);
                        }
                    }

                default:
                    throw new InvalidOperationException();
            }
        }

        internal virtual void UpdateDnssecStatus()
        {
            if (!_entries.ContainsKey(DnsResourceRecordType.DNSKEY))
                _dnssecStatus = AuthZoneDnssecStatus.Unsigned;
            else if (_entries.ContainsKey(DnsResourceRecordType.NSEC3PARAM))
                _dnssecStatus = AuthZoneDnssecStatus.SignedWithNSEC3;
            else
                _dnssecStatus = AuthZoneDnssecStatus.SignedWithNSEC;
        }

        #endregion

        #region public

        public async Task<IReadOnlyList<NameServerAddress>> GetPrimaryNameServerAddressesAsync(DnsServer dnsServer)
        {
            DnsResourceRecord soaRecord = _entries[DnsResourceRecordType.SOA][0];

            IReadOnlyList<NameServerAddress> primaryNameServers = soaRecord.GetPrimaryNameServers();
            if (primaryNameServers.Count > 0)
            {
                List<NameServerAddress> resolvedNameServers = new List<NameServerAddress>(primaryNameServers.Count * 2);

                foreach (NameServerAddress nameServer in primaryNameServers)
                {
                    if (nameServer.IsIPEndPointStale)
                        await ResolveNameServerAddressesAsync(dnsServer, nameServer.Host, nameServer.Port, nameServer.Protocol, resolvedNameServers);
                    else
                        resolvedNameServers.Add(nameServer);
                }

                return resolvedNameServers;
            }

            string primaryNameServer = (soaRecord.RDATA as DnsSOARecord).PrimaryNameServer;
            IReadOnlyList<DnsResourceRecord> nsRecords = GetRecords(DnsResourceRecordType.NS); //stub zone has no authority so cant use QueryRecords

            List<NameServerAddress> nameServers = new List<NameServerAddress>(nsRecords.Count * 2);

            foreach (DnsResourceRecord nsRecord in nsRecords)
            {
                if (nsRecord.IsDisabled())
                    continue;

                if (primaryNameServer.Equals((nsRecord.RDATA as DnsNSRecord).NameServer, StringComparison.OrdinalIgnoreCase))
                {
                    //found primary NS
                    await ResolveNameServerAddressesAsync(dnsServer, nsRecord, nameServers);
                    break;
                }
            }

            if (nameServers.Count < 1)
                await ResolveNameServerAddressesAsync(dnsServer, primaryNameServer, 53, DnsTransportProtocol.Udp, nameServers);

            return nameServers;
        }

        public async Task<IReadOnlyList<NameServerAddress>> GetSecondaryNameServerAddressesAsync(DnsServer dnsServer)
        {
            string primaryNameServer = (_entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecord).PrimaryNameServer;
            IReadOnlyList<DnsResourceRecord> nsRecords = GetRecords(DnsResourceRecordType.NS); //stub zone has no authority so cant use QueryRecords

            List<NameServerAddress> nameServers = new List<NameServerAddress>(nsRecords.Count * 2);

            foreach (DnsResourceRecord nsRecord in nsRecords)
            {
                if (nsRecord.IsDisabled())
                    continue;

                if (primaryNameServer.Equals((nsRecord.RDATA as DnsNSRecord).NameServer, StringComparison.OrdinalIgnoreCase))
                    continue; //skip primary name server

                await ResolveNameServerAddressesAsync(dnsServer, nsRecord, nameServers);
            }

            return nameServers;
        }

        public async Task<IReadOnlyList<NameServerAddress>> GetAllNameServerAddressesAsync(DnsServer dnsServer)
        {
            IReadOnlyList<NameServerAddress> primaryNameServers = await GetPrimaryNameServerAddressesAsync(dnsServer);
            IReadOnlyList<NameServerAddress> secondaryNameServers = await GetSecondaryNameServerAddressesAsync(dnsServer);

            if (secondaryNameServers.Count < 1)
                return primaryNameServers;

            List<NameServerAddress> allNameServers = new List<NameServerAddress>(primaryNameServers.Count + secondaryNameServers.Count);

            allNameServers.AddRange(primaryNameServers);
            allNameServers.AddRange(secondaryNameServers);

            return allNameServers;
        }

        #endregion

        #region properties

        public virtual AuthZoneTransfer ZoneTransfer
        {
            get { return _zoneTransfer; }
            set { _zoneTransfer = value; }
        }

        public IReadOnlyCollection<IPAddress> ZoneTransferNameServers
        {
            get { return _zoneTransferNameServers; }
            set
            {
                if ((value is not null) && (value.Count > byte.MaxValue))
                    throw new ArgumentOutOfRangeException(nameof(ZoneTransferNameServers), "Name server addresses cannot be more than 255.");

                _zoneTransferNameServers = value;
            }
        }

        public virtual AuthZoneNotify Notify
        {
            get { return _notify; }
            set { _notify = value; }
        }

        public IReadOnlyCollection<IPAddress> NotifyNameServers
        {
            get { return _notifyNameServers; }
            set
            {
                if ((value is not null) && (value.Count > byte.MaxValue))
                    throw new ArgumentOutOfRangeException(nameof(NotifyNameServers), "Name server addresses cannot be more than 255.");

                _notifyNameServers = value;
            }
        }

        public AuthZoneDnssecStatus DnssecStatus
        { get { return _dnssecStatus; } }

        #endregion
    }
}
