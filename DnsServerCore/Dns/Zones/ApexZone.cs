/*
Technitium DNS Server
Copyright (C) 2023  Shreyas Zare (shreyas@technitium.com)

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
using System.Threading;
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
        AllowOnlySpecifiedNameServers = 3,
        AllowBothZoneAndSpecifiedNameServers = 4
    }

    public enum AuthZoneNotify : byte
    {
        None = 0,
        ZoneNameServers = 1,
        SpecifiedNameServers = 2,
        BothZoneAndSpecifiedNameServers = 3
    }

    public enum AuthZoneUpdate : byte
    {
        Deny = 0,
        Allow = 1,
        AllowOnlyZoneNameServers = 2,
        AllowOnlySpecifiedIpAddresses = 3,
        AllowBothZoneNameServersAndSpecifiedIpAddresses = 4
    }

    abstract class ApexZone : AuthZone, IDisposable
    {
        #region variables

        protected AuthZoneTransfer _zoneTransfer;
        protected IReadOnlyCollection<IPAddress> _zoneTransferNameServers;
        protected AuthZoneNotify _notify;
        protected IReadOnlyCollection<IPAddress> _notifyNameServers;
        protected AuthZoneUpdate _update;
        protected IReadOnlyCollection<IPAddress> _updateIpAddresses;
        protected List<DnsResourceRecord> _zoneHistory; //for IXFR support
        protected IReadOnlyDictionary<string, object> _zoneTransferTsigKeyNames;
        protected IReadOnlyDictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>> _updateSecurityPolicies;
        protected AuthZoneDnssecStatus _dnssecStatus;

        Timer _notifyTimer;
        bool _notifyTimerTriggered;
        const int NOTIFY_TIMER_INTERVAL = 10000;
        List<string> _notifyList;
        List<string> _notifyFailed;
        const int NOTIFY_TIMEOUT = 10000;
        const int NOTIFY_RETRIES = 5;

        protected bool _syncFailed;

        #endregion

        #region constructor

        protected ApexZone(AuthZoneInfo zoneInfo)
            : base(zoneInfo)
        {
            _zoneTransfer = zoneInfo.ZoneTransfer;
            _zoneTransferNameServers = zoneInfo.ZoneTransferNameServers;
            _notify = zoneInfo.Notify;
            _notifyNameServers = zoneInfo.NotifyNameServers;
            _update = zoneInfo.Update;
            _updateIpAddresses = zoneInfo.UpdateIpAddresses;

            if (zoneInfo.ZoneHistory is null)
                _zoneHistory = new List<DnsResourceRecord>();
            else
                _zoneHistory = new List<DnsResourceRecord>(zoneInfo.ZoneHistory);

            _zoneTransferTsigKeyNames = zoneInfo.ZoneTransferTsigKeyNames;
            _updateSecurityPolicies = zoneInfo.UpdateSecurityPolicies;
        }

        protected ApexZone(string name)
            : base(name)
        {
            _zoneHistory = new List<DnsResourceRecord>();
        }

        #endregion

        #region IDisposable

        bool _disposed;

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_notifyTimer is not null)
                    _notifyTimer.Dispose();
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region protected

        protected void CleanupHistory(List<DnsResourceRecord> history)
        {
            DnsSOARecordData soa = _entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecordData;
            DateTime expiry = DateTime.UtcNow.AddSeconds(-soa.Expire);
            int index = 0;

            while (index < history.Count)
            {
                //check difference sequence
                if (history[index].GetAuthRecordInfo().DeletedOn > expiry)
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

        protected void InitNotify(DnsServer dnsServer)
        {
            _notifyTimer = new Timer(NotifyTimerCallback, dnsServer, Timeout.Infinite, Timeout.Infinite);
            _notifyList = new List<string>();
            _notifyFailed = new List<string>();
        }

        protected void DisableNotifyTimer()
        {
            if (_notifyTimer is not null)
                _notifyTimer.Change(Timeout.Infinite, Timeout.Infinite);
        }

        #endregion

        #region private

        private async void NotifyTimerCallback(object state)
        {
            DnsServer dnsServer = state as DnsServer;

            async Task NotifyZoneNameServers(List<string> existingNameServers)
            {
                string primaryNameServer = (_entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecordData).PrimaryNameServer;
                IReadOnlyList<DnsResourceRecord> nsRecords = GetRecords(DnsResourceRecordType.NS); //stub zone has no authority so cant use QueryRecords

                //notify all secondary name servers
                foreach (DnsResourceRecord nsRecord in nsRecords)
                {
                    if (nsRecord.GetAuthRecordInfo().Disabled)
                        continue;

                    string nameServerHost = (nsRecord.RDATA as DnsNSRecordData).NameServer;

                    if (primaryNameServer.Equals(nameServerHost, StringComparison.OrdinalIgnoreCase))
                        continue; //skip primary name server

                    existingNameServers.Add(nameServerHost);

                    List<NameServerAddress> nameServers = new List<NameServerAddress>(2);
                    await ResolveNameServerAddressesAsync(dnsServer, nsRecord, nameServers);

                    if (nameServers.Count > 0)
                    {
                        _ = NotifyNameServerAsync(dnsServer, nameServerHost, nameServers);
                    }
                    else
                    {
                        lock (_notifyFailed)
                        {
                            if (!_notifyFailed.Contains(nameServerHost))
                                _notifyFailed.Add(nameServerHost);
                        }

                        LogManager log = dnsServer.LogManager;
                        if (log != null)
                            log.Write("DNS Server failed to notify name server '" + nameServerHost + "' due to failure in resolving its IP address for zone: " + (_name == "" ? "<root>" : _name));
                    }
                }
            }

            void NotifySpecifiedNameServers(List<string> existingNameServers)
            {
                IReadOnlyCollection<IPAddress> specifiedNameServers = _notifyNameServers;
                if (specifiedNameServers is not null)
                {
                    foreach (IPAddress specifiedNameServer in specifiedNameServers)
                    {
                        string nameServerHost = specifiedNameServer.ToString();
                        existingNameServers.Add(nameServerHost);

                        _ = NotifyNameServerAsync(dnsServer, nameServerHost, new NameServerAddress[] { new NameServerAddress(specifiedNameServer) });
                    }
                }
            }

            try
            {
                List<string> existingNameServers = new List<string>();

                switch (_notify)
                {
                    case AuthZoneNotify.ZoneNameServers:
                        await NotifyZoneNameServers(existingNameServers);
                        break;

                    case AuthZoneNotify.SpecifiedNameServers:
                        NotifySpecifiedNameServers(existingNameServers);
                        break;

                    case AuthZoneNotify.BothZoneAndSpecifiedNameServers:
                        await NotifyZoneNameServers(existingNameServers);
                        NotifySpecifiedNameServers(existingNameServers);
                        break;
                }

                //remove non-existent name servers from notify failed list
                lock (_notifyFailed)
                {
                    List<string> toRemove = new List<string>();

                    foreach (string failedNameServer in _notifyFailed)
                    {
                        bool found = false;

                        foreach (string existingNameServer in existingNameServers)
                        {
                            if (failedNameServer.Equals(existingNameServer))
                            {
                                found = true;
                                break;
                            }
                        }

                        if (!found)
                            toRemove.Add(failedNameServer);
                    }

                    if (toRemove.Count > 0)
                    {
                        foreach (string failedNameServer in toRemove)
                            _notifyFailed.Remove(failedNameServer);
                    }
                }
            }
            catch (Exception ex)
            {
                LogManager log = dnsServer.LogManager;
                if (log != null)
                    log.Write(ex);
            }
            finally
            {
                _notifyTimerTriggered = false;
            }
        }

        private async Task NotifyNameServerAsync(DnsServer dnsServer, string nameServerHost, IReadOnlyList<NameServerAddress> nameServers)
        {
            //use notify list to prevent multiple threads from notifying the same name server
            lock (_notifyList)
            {
                if (_notifyList.Contains(nameServerHost))
                    return; //already notifying the name server in another thread

                _notifyList.Add(nameServerHost);
            }

            try
            {
                DnsClient client = new DnsClient(nameServers);

                client.Proxy = dnsServer.Proxy;
                client.Timeout = NOTIFY_TIMEOUT;
                client.Retries = NOTIFY_RETRIES;

                DnsDatagram notifyRequest = new DnsDatagram(0, false, DnsOpcode.Notify, true, false, false, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN) }, _entries[DnsResourceRecordType.SOA]);
                DnsDatagram response = await client.ResolveAsync(notifyRequest);

                switch (response.RCODE)
                {
                    case DnsResponseCode.NoError:
                    case DnsResponseCode.NotImplemented:
                        {
                            //transaction complete
                            lock (_notifyFailed)
                            {
                                _notifyFailed.Remove(nameServerHost);
                            }

                            LogManager log = dnsServer.LogManager;
                            if (log is not null)
                                log.Write("DNS Server successfully notified name server '" + nameServerHost + "' for zone: " + (_name == "" ? "<root>" : _name));
                        }
                        break;

                    default:
                        {
                            //transaction failed
                            lock (_notifyFailed)
                            {
                                if (!_notifyFailed.Contains(nameServerHost))
                                    _notifyFailed.Add(nameServerHost);
                            }

                            LogManager log = dnsServer.LogManager;
                            if (log is not null)
                                log.Write("DNS Server failed to notify name server '" + nameServerHost + "' (RCODE=" + response.RCODE.ToString() + ") for zone : " + (_name == "" ? "<root>" : _name));
                        }
                        break;
                }
            }
            catch (Exception ex)
            {
                lock (_notifyFailed)
                {
                    if (!_notifyFailed.Contains(nameServerHost))
                        _notifyFailed.Add(nameServerHost);
                }

                dnsServer.LogManager?.Write("DNS Server failed to notify name server '" + nameServerHost + "' for zone: " + (_name == "" ? "<root>" : _name) + "\r\n" + ex.ToString());
            }
            finally
            {
                lock (_notifyList)
                {
                    _notifyList.Remove(nameServerHost);
                }
            }
        }

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
            string nsDomain = (nsRecord.RDATA as DnsNSRecordData).NameServer;

            IReadOnlyList<DnsResourceRecord> glueRecords = nsRecord.GetAuthRecordInfo().GlueRecords;
            if (glueRecords is not null)
            {
                foreach (DnsResourceRecord glueRecord in glueRecords)
                {
                    switch (glueRecord.Type)
                    {
                        case DnsResourceRecordType.A:
                            outNameServers.Add(new NameServerAddress(nsDomain, (glueRecord.RDATA as DnsARecordData).Address));
                            break;

                        case DnsResourceRecordType.AAAA:
                            if (dnsServer.PreferIPv6)
                                outNameServers.Add(new NameServerAddress(nsDomain, (glueRecord.RDATA as DnsAAAARecordData).Address));

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

        public IReadOnlyList<DnsResourceRecord> GetZoneHistory()
        {
            lock (_zoneHistory)
            {
                return _zoneHistory.ToArray();
            }
        }

        public void TriggerNotify()
        {
            if (_disabled)
                return;

            if (_notify == AuthZoneNotify.None)
            {
                if (_notifyFailed is not null)
                {
                    lock (_notifyFailed)
                    {
                        _notifyFailed.Clear();
                    }
                }

                return;
            }

            if (_notifyTimerTriggered)
                return;

            if (_disposed)
                return;

            if (_notifyTimer is null)
                return;

            _notifyTimer.Change(NOTIFY_TIMER_INTERVAL, Timeout.Infinite);
            _notifyTimerTriggered = true;
        }

        public async Task<IReadOnlyList<NameServerAddress>> GetPrimaryNameServerAddressesAsync(DnsServer dnsServer)
        {
            DnsResourceRecord soaRecord = _entries[DnsResourceRecordType.SOA][0];

            IReadOnlyList<NameServerAddress> primaryNameServers = soaRecord.GetAuthRecordInfo().PrimaryNameServers;
            if (primaryNameServers is not null)
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

            string primaryNameServer = (soaRecord.RDATA as DnsSOARecordData).PrimaryNameServer;
            IReadOnlyList<DnsResourceRecord> nsRecords = GetRecords(DnsResourceRecordType.NS); //stub zone has no authority so cant use QueryRecords

            List<NameServerAddress> nameServers = new List<NameServerAddress>(nsRecords.Count * 2);

            foreach (DnsResourceRecord nsRecord in nsRecords)
            {
                if (nsRecord.GetAuthRecordInfo().Disabled)
                    continue;

                if (primaryNameServer.Equals((nsRecord.RDATA as DnsNSRecordData).NameServer, StringComparison.OrdinalIgnoreCase))
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
            string primaryNameServer = (_entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecordData).PrimaryNameServer;
            IReadOnlyList<DnsResourceRecord> nsRecords = GetRecords(DnsResourceRecordType.NS); //stub zone has no authority so cant use QueryRecords

            List<NameServerAddress> nameServers = new List<NameServerAddress>(nsRecords.Count * 2);

            foreach (DnsResourceRecord nsRecord in nsRecords)
            {
                if (nsRecord.GetAuthRecordInfo().Disabled)
                    continue;

                if (primaryNameServer.Equals((nsRecord.RDATA as DnsNSRecordData).NameServer, StringComparison.OrdinalIgnoreCase))
                    continue; //skip primary name server

                await ResolveNameServerAddressesAsync(dnsServer, nsRecord, nameServers);
            }

            return nameServers;
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
            set
            {
                if (_notify != value)
                {
                    _notify = value;

                    lock (_notifyFailed)
                    {
                        _notifyFailed.Clear();
                    }
                }
            }
        }

        public IReadOnlyCollection<IPAddress> NotifyNameServers
        {
            get { return _notifyNameServers; }
            set
            {
                if ((value is not null) && (value.Count > byte.MaxValue))
                    throw new ArgumentOutOfRangeException(nameof(NotifyNameServers), "Name server addresses cannot be more than 255.");

                if (_notifyNameServers != value)
                {
                    _notifyNameServers = value;

                    lock (_notifyFailed)
                    {
                        _notifyFailed.Clear();
                    }
                }
            }
        }

        public virtual AuthZoneUpdate Update
        {
            get { return _update; }
            set { _update = value; }
        }

        public IReadOnlyCollection<IPAddress> UpdateIpAddresses
        {
            get { return _updateIpAddresses; }
            set
            {
                if ((value is not null) && (value.Count > byte.MaxValue))
                    throw new ArgumentOutOfRangeException(nameof(ZoneTransferNameServers), "IP addresses cannot be more than 255.");

                _updateIpAddresses = value;
            }
        }

        public IReadOnlyDictionary<string, object> ZoneTransferTsigKeyNames
        {
            get { return _zoneTransferTsigKeyNames; }
            set { _zoneTransferTsigKeyNames = value; }
        }

        public IReadOnlyDictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>> UpdateSecurityPolicies
        {
            get { return _updateSecurityPolicies; }
            set { _updateSecurityPolicies = value; }
        }

        public bool NotifyFailed
        {
            get
            {
                if (_notifyFailed is null)
                    return false;

                lock (_notifyFailed)
                {
                    return _notifyFailed.Count > 0;
                }
            }
        }

        public bool SyncFailed
        { get { return _syncFailed; } }

        public AuthZoneDnssecStatus DnssecStatus
        { get { return _dnssecStatus; } }

        #endregion
    }
}
