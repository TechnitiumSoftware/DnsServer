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
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    class SecondaryCatalogZone : SecondaryForwarderZone
    {
        #region events

        public event EventHandler<SecondaryCatalogEventArgs> ZoneAdded;
        public event EventHandler<SecondaryCatalogEventArgs> ZoneRemoved;

        #endregion

        #region variables

        readonly static IReadOnlyCollection<NetworkAccessControl> _allowACL =
            [
                new NetworkAccessControl(IPAddress.Any, 0),
                new NetworkAccessControl(IPAddress.IPv6Any, 0)
            ];

        readonly static IReadOnlyCollection<NetworkAccessControl> _queryAccessAllowOnlyPrivateNetworksACL =
            [
                new NetworkAccessControl(IPAddress.Parse("127.0.0.0"), 8),
                new NetworkAccessControl(IPAddress.Parse("10.0.0.0"), 8),
                new NetworkAccessControl(IPAddress.Parse("100.64.0.0"), 10),
                new NetworkAccessControl(IPAddress.Parse("169.254.0.0"), 16),
                new NetworkAccessControl(IPAddress.Parse("172.16.0.0"), 12),
                new NetworkAccessControl(IPAddress.Parse("192.168.0.0"), 16),
                new NetworkAccessControl(IPAddress.Parse("2000::"), 3, true),
                new NetworkAccessControl(IPAddress.IPv6Any, 0)
            ];

        readonly static IReadOnlyCollection<NetworkAccessControl> _allowOnlyZoneNameServersACL =
            [
                new NetworkAccessControl(IPAddress.Parse("224.0.0.0"), 32)
            ];

        readonly static IReadOnlyCollection<NetworkAccessControl> _denyACL =
            [
                new NetworkAccessControl(IPAddress.Parse("127.0.0.0"), 8),
                new NetworkAccessControl(IPAddress.Parse("::1"), 128)
            ];

        readonly static NetworkAccessControl _allowZoneNameServersAndUseSpecifiedNetworkACL = new NetworkAccessControl(IPAddress.Parse("224.0.0.0"), 32);

        Dictionary<string, string> _membersIndex = new Dictionary<string, string>();

        #endregion

        #region constructor

        public SecondaryCatalogZone(DnsServer dnsServer, AuthZoneInfo zoneInfo)
            : base(dnsServer, zoneInfo)
        { }

        public SecondaryCatalogZone(DnsServer dnsServer, string name, IReadOnlyList<NameServerAddress> primaryNameServerAddresses, DnsTransportProtocol primaryZoneTransferProtocol = DnsTransportProtocol.Tcp, string primaryZoneTransferTsigKeyName = null)
            : base(dnsServer, name, primaryNameServerAddresses, primaryZoneTransferProtocol, primaryZoneTransferTsigKeyName)
        { }

        #endregion

        #region protected

        protected override void InitZone()
        {
            //init secondary catalog zone with dummy SOA and NS records
            DnsSOARecordData soa = new DnsSOARecordData("invalid", "invalid", 0, 300, 60, 604800, 900);
            DnsResourceRecord soaRecord = new DnsResourceRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN, 0, soa);
            soaRecord.GetAuthGenericRecordInfo().LastModified = DateTime.UtcNow;

            _entries[DnsResourceRecordType.SOA] = [soaRecord];
            _entries[DnsResourceRecordType.NS] = [new DnsResourceRecord(_name, DnsResourceRecordType.NS, DnsClass.IN, 0, new DnsNSRecordData("invalid"))];
        }

        #endregion

        #region internal

        internal void BuildMembersIndex()
        {
            Dictionary<string, string> membersIndex = new Dictionary<string, string>();

            foreach (KeyValuePair<string, string> memberEntry in EnumerateCatalogMemberZones(_dnsServer))
                membersIndex.TryAdd(memberEntry.Key.ToLowerInvariant(), memberEntry.Value);

            _membersIndex = membersIndex;
        }

        #endregion

        #region secondary catalog

        public IReadOnlyCollection<string> GetAllMemberZoneNames()
        {
            return _membersIndex.Keys;
        }

        protected override async Task FinalizeZoneTransferAsync()
        {
            //secondary catalog does not maintain zone history; no need to call base method
            string version = GetVersion();
            if ((version is null) || !version.Equals("2", StringComparison.OrdinalIgnoreCase))
            {
                _dnsServer.LogManager.Write("Failed to provision Secondary Catalog zone '" + ToString() + "': catalog version not supported.");
                return;
            }

            Dictionary<string, string> updatedMembersIndex = new Dictionary<string, string>();

            foreach (KeyValuePair<string, string> memberEntry in EnumerateCatalogMemberZones(_dnsServer))
                updatedMembersIndex.TryAdd(memberEntry.Key, memberEntry.Value);

            Dictionary<string, object> membersToRemove = new Dictionary<string, object>();
            Dictionary<string, string> membersToAdd = new Dictionary<string, string>();

            foreach (KeyValuePair<string, string> memberEntry in _membersIndex)
            {
                if (!updatedMembersIndex.TryGetValue(memberEntry.Key, out string updatedMembersZoneDomain))
                {
                    //member was removed from catalog zone; remove local zone
                    membersToRemove.Add(memberEntry.Key, null);
                }
                else if (!memberEntry.Value.Equals(updatedMembersZoneDomain, StringComparison.OrdinalIgnoreCase))
                {
                    //member exists but label does not match; reprovision zone
                    membersToRemove.Add(memberEntry.Key, null);
                    membersToAdd.Add(memberEntry.Key, updatedMembersZoneDomain);
                }
            }

            foreach (KeyValuePair<string, string> updatedMemberEntry in updatedMembersIndex)
            {
                if (_membersIndex.TryGetValue(updatedMemberEntry.Key, out _))
                {
                    ApexZone apexZone = _dnsServer.AuthZoneManager.GetApexZone(updatedMemberEntry.Key);
                    if (apexZone is not null)
                        continue; //zone already exists; do nothing
                }

                //member was added to catalog zone; provision zone
                membersToAdd.TryAdd(updatedMemberEntry.Key, updatedMemberEntry.Value);
            }

            //set global custom properties
            UpdateGlobalAllowQueryProperty();
            UpdateGlobalAllowTransferAndTsigKeyNamesProperties();

            //add and remove member zones
            if ((membersToRemove.Count > 0) || (membersToAdd.Count > 0))
                await AddAndRemoveMemberZonesAsync(membersToRemove, membersToAdd);

            //set member zone custom properties
            if (updatedMembersIndex.Count > 0)
                UpdateMemberZoneCustomProperties(updatedMembersIndex);

            _membersIndex = updatedMembersIndex;

            _dnsServer.AuthZoneManager.SaveZoneFile(_name);
        }

        protected override async Task FinalizeIncrementalZoneTransferAsync(IReadOnlyList<DnsResourceRecord> historyRecords)
        {
            //secondary catalog does not maintain zone history; no need to call base method
            string version = GetVersion();
            if ((version is null) || !version.Equals("2", StringComparison.OrdinalIgnoreCase))
            {
                _dnsServer.LogManager.Write("Failed to provision Secondary Catalog zone '" + ToString() + "': catalog version not supported.");
                return;
            }

            bool isAddHistoryRecord = false;
            bool updateGlobalAllowQueryProperty = false;
            bool updateGlobalAllowTransferAndTsigKeyNamesProperties = false;
            Dictionary<string, object> membersToRemove = new Dictionary<string, object>();
            Dictionary<string, string> membersToAdd = new Dictionary<string, string>();
            Dictionary<string, string> membersToUpdate = new Dictionary<string, string>();

            //inspect records in history
            for (int i = 1; i < historyRecords.Count; i++)
            {
                DnsResourceRecord historyRecord = historyRecords[i];
                if (historyRecord.Type == DnsResourceRecordType.SOA)
                {
                    isAddHistoryRecord = true; //removed records completed
                    continue;
                }

                if (historyRecord.Name.Length == _name.Length)
                    continue; //skip apex records

                string subdomain = historyRecord.Name.Substring(0, historyRecord.Name.Length - _name.Length - 1).ToLowerInvariant();
                string[] labels = subdomain.Split('.');
                Array.Reverse(labels);

                switch (labels[0])
                {
                    case "ext":
                        if (labels.Length > 1)
                        {
                            switch (labels[1])
                            {
                                case "allow-query":
                                    updateGlobalAllowQueryProperty = true;
                                    break;

                                case "allow-transfer":
                                case "transfer-tsig-key-names":
                                    updateGlobalAllowTransferAndTsigKeyNamesProperties = true;
                                    break;
                            }
                        }
                        break;

                    case "zones":
                        if (labels.Length == 2)
                        {
                            if (historyRecord.Type == DnsResourceRecordType.PTR)
                            {
                                string memberZoneName = (historyRecord.RDATA as DnsPTRRecordData).Domain.ToLowerInvariant();

                                if (isAddHistoryRecord)
                                {
                                    string memberZoneDomain = subdomain + "." + _name;

                                    membersToAdd.TryAdd(memberZoneName, memberZoneDomain);
                                    membersToUpdate.TryAdd(memberZoneName, memberZoneDomain);
                                }
                                else
                                {
                                    membersToRemove.TryAdd(memberZoneName, null);
                                }
                            }
                        }
                        else if (labels.Length > 2)
                        {
                            switch (labels[2])
                            {
                                case "ext":
                                case "coo":
                                    string memberZoneDomain = labels[1] + "." + labels[0] + "." + _name;
                                    DnsResourceRecord prevHistoryRecord = historyRecords[i - 1];

                                    if (prevHistoryRecord.Name.EndsWith(memberZoneDomain, StringComparison.OrdinalIgnoreCase))
                                        break; //skip since its same member zone's custom property

                                    IReadOnlyList<DnsResourceRecord> ptrRecords = _dnsServer.AuthZoneManager.GetRecords(_name, memberZoneDomain, DnsResourceRecordType.PTR);
                                    if (ptrRecords.Count > 0)
                                        membersToUpdate.TryAdd((ptrRecords[0].RDATA as DnsPTRRecordData).Domain.ToLowerInvariant(), memberZoneDomain);

                                    break;
                            }
                        }

                        break;
                }
            }

            //apply changes
            if (updateGlobalAllowQueryProperty)
                UpdateGlobalAllowQueryProperty();

            if (updateGlobalAllowTransferAndTsigKeyNamesProperties)
                UpdateGlobalAllowTransferAndTsigKeyNamesProperties();

            if ((membersToRemove.Count > 0) || (membersToAdd.Count > 0))
                await AddAndRemoveMemberZonesAsync(membersToRemove, membersToAdd);

            if (membersToUpdate.Count > 0)
                UpdateMemberZoneCustomProperties(membersToUpdate);

            if ((membersToRemove.Count > 0) || (membersToAdd.Count > 0))
            {
                //update members index
                Dictionary<string, string> updatedMembersIndex = new Dictionary<string, string>(_membersIndex);

                foreach (KeyValuePair<string, object> removedMember in membersToRemove)
                    updatedMembersIndex.Remove(removedMember.Key);

                foreach (KeyValuePair<string, string> addedMember in membersToAdd)
                    updatedMembersIndex.TryAdd(addedMember.Key, addedMember.Value);

                _membersIndex = updatedMembersIndex;
            }

            _dnsServer.AuthZoneManager.SaveZoneFile(_name);
        }

        private async Task AddAndRemoveMemberZonesAsync(Dictionary<string, object> membersToRemove, Dictionary<string, string> membersToAdd)
        {
            //remove zones
            foreach (KeyValuePair<string, object> removeMember in membersToRemove)
            {
                ApexZone apexZone = _dnsServer.AuthZoneManager.GetApexZone(removeMember.Key);
                if ((apexZone is not null) && _name.Equals(apexZone.CatalogZoneName, StringComparison.OrdinalIgnoreCase))
                    DeleteMemberZone(apexZone);
            }

            //add zones
            List<Task> tasks = new List<Task>(membersToAdd.Count);

            foreach (KeyValuePair<string, string> addMember in membersToAdd)
            {
                ApexZone apexZone = _dnsServer.AuthZoneManager.GetApexZone(addMember.Key);
                if (apexZone is null)
                {
                    //create zone
                    AuthZoneType zoneType = GetZoneTypeProperty(addMember.Value);
                    switch (zoneType)
                    {
                        case AuthZoneType.Primary:
                            {
                                TaskCompletionSource taskSource = new TaskCompletionSource();

                                if (_dnsServer.TryQueueResolverTask(async delegate (object state)
                                {
                                    //create secondary zone
                                    try
                                    {
                                        IReadOnlyList<NameServerAddress> primaryNameServerAddresses;
                                        DnsTransportProtocol primaryZoneTransferProtocol;
                                        string primaryZoneTransferTsigKeyName;

                                        List<Tuple<IPAddress, string>> primaries = GetPrimariesProperty(addMember.Value);
                                        if (primaries.Count == 0)
                                            primaries = GetPrimariesProperty(_name);

                                        if (primaries.Count == 0)
                                        {
                                            primaryNameServerAddresses = PrimaryNameServerAddresses;
                                            primaryZoneTransferProtocol = PrimaryZoneTransferProtocol;
                                            primaryZoneTransferTsigKeyName = PrimaryZoneTransferTsigKeyName;
                                        }
                                        else
                                        {
                                            Tuple<IPAddress, string> primary = primaries[0];

                                            primaryNameServerAddresses = [new NameServerAddress(primary.Item1, DnsTransportProtocol.Tcp)];
                                            primaryZoneTransferProtocol = DnsTransportProtocol.Tcp;
                                            primaryZoneTransferTsigKeyName = primary.Item2;
                                        }

                                        AuthZoneInfo zoneInfo = await _dnsServer.AuthZoneManager.CreateSecondaryZoneAsync(addMember.Key, primaryNameServerAddresses, primaryZoneTransferProtocol, primaryZoneTransferTsigKeyName, false, true);

                                        //set as catalog zone member
                                        zoneInfo.ApexZone.CatalogZoneName = _name;

                                        //raise event
                                        ZoneAdded?.Invoke(this, new SecondaryCatalogEventArgs(zoneInfo));

                                        //write log
                                        _dnsServer.LogManager.Write(zoneInfo.TypeName + " zone '" + zoneInfo.DisplayName + "' was added via Secondary Catalog zone '" + ToString() + "' sucessfully.");
                                    }
                                    catch (Exception ex)
                                    {
                                        _dnsServer.LogManager.Write(ex);
                                    }
                                    finally
                                    {
                                        (state as TaskCompletionSource).TrySetResult();
                                    }
                                }, taskSource))
                                {
                                    tasks.Add(taskSource.Task);
                                }
                            }
                            break;

                        case AuthZoneType.Stub:
                            {
                                TaskCompletionSource taskSource = new TaskCompletionSource();

                                if (_dnsServer.TryQueueResolverTask(async delegate (object state)
                                {
                                    //create stub zone
                                    try
                                    {
                                        IReadOnlyList<NameServerAddress> primaryNameServerAddresses = GetPrimaryAddressesProperty(addMember.Value);

                                        AuthZoneInfo zoneInfo = await _dnsServer.AuthZoneManager.CreateStubZoneAsync(addMember.Key, primaryNameServerAddresses, true);

                                        //set as catalog zone member
                                        zoneInfo.ApexZone.CatalogZoneName = _name;

                                        //raise event
                                        ZoneAdded?.Invoke(this, new SecondaryCatalogEventArgs(zoneInfo));

                                        //write log
                                        _dnsServer.LogManager.Write(zoneInfo.TypeName + " zone '" + zoneInfo.DisplayName + "' was added via Secondary Catalog zone '" + ToString() + "' sucessfully.");
                                    }
                                    catch (Exception ex)
                                    {
                                        _dnsServer.LogManager.Write(ex);
                                    }
                                    finally
                                    {
                                        (state as TaskCompletionSource).TrySetResult();
                                    }
                                }, taskSource))
                                {
                                    tasks.Add(taskSource.Task);
                                }
                            }
                            break;

                        case AuthZoneType.Forwarder:
                            {
                                //create secondary forwarder zone
                                try
                                {
                                    AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.CreateSecondaryForwarderZone(addMember.Key, PrimaryNameServerAddresses, PrimaryZoneTransferProtocol, PrimaryZoneTransferTsigKeyName);

                                    //set as catalog zone member
                                    zoneInfo.ApexZone.CatalogZoneName = _name;

                                    //raise event
                                    ZoneAdded?.Invoke(this, new SecondaryCatalogEventArgs(zoneInfo));

                                    //write log
                                    _dnsServer.LogManager.Write(zoneInfo.TypeName + " zone '" + zoneInfo.DisplayName + "' was added via Secondary Catalog zone '" + ToString() + "' sucessfully.");
                                }
                                catch (Exception ex)
                                {
                                    _dnsServer.LogManager.Write(ex);
                                }
                            }
                            break;
                    }
                }
            }

            //wait for all zones to be added
            foreach (Task task in tasks)
                await task;
        }

        private void UpdateGlobalAllowQueryProperty()
        {
            //allow query global custom property
            IReadOnlyCollection<NetworkAccessControl> globalAllowQueryACL = GetAllowQueryProperty(_name);
            if (globalAllowQueryACL.Count > 0)
            {
                _queryAccess = GetQueryAccessType(globalAllowQueryACL);
                switch (_queryAccess)
                {
                    case AuthZoneQueryAccess.UseSpecifiedNetworkACL:
                        QueryAccessNetworkACL = globalAllowQueryACL;
                        break;

                    case AuthZoneQueryAccess.AllowZoneNameServersAndUseSpecifiedNetworkACL:
                        QueryAccessNetworkACL = GetFilteredACL(globalAllowQueryACL);
                        break;

                    default:
                        QueryAccessNetworkACL = null;
                        break;
                }
            }
            else
            {
                _queryAccess = AuthZoneQueryAccess.Allow;
                QueryAccessNetworkACL = null;
            }
        }

        private void UpdateGlobalAllowTransferAndTsigKeyNamesProperties()
        {
            //allow transfer global custom property
            IReadOnlyCollection<NetworkAccessControl> globalAllowTransferACL = GetAllowTransferProperty(_name);
            if (globalAllowTransferACL.Count > 0)
            {
                _zoneTransfer = GetZoneTransferType(globalAllowTransferACL);
                switch (_zoneTransfer)
                {
                    case AuthZoneTransfer.UseSpecifiedNetworkACL:
                        ZoneTransferNetworkACL = globalAllowTransferACL;
                        break;

                    case AuthZoneTransfer.AllowZoneNameServersAndUseSpecifiedNetworkACL:
                        ZoneTransferNetworkACL = GetFilteredACL(globalAllowTransferACL);
                        break;

                    default:
                        ZoneTransferNetworkACL = null;
                        break;
                }

                //zone tranfer tsig key names global custom property
                ZoneTransferTsigKeyNames = GetZoneTransferTsigKeyNamesProperty(_name);
            }
            else
            {
                _zoneTransfer = AuthZoneTransfer.Deny;
                ZoneTransferNetworkACL = null;
                ZoneTransferTsigKeyNames = null;
            }
        }

        private void UpdateMemberZoneCustomProperties(Dictionary<string, string> membersToUpdate)
        {
            foreach (KeyValuePair<string, string> updatedMemberEntry in membersToUpdate)
            {
                ApexZone memberApexZone = _dnsServer.AuthZoneManager.GetApexZone(updatedMemberEntry.Key);
                if ((memberApexZone is not null) && _name.Equals(memberApexZone.CatalogZoneName, StringComparison.OrdinalIgnoreCase))
                {
                    //change of ownership property
                    {
                        string newCatalogZoneName = GetChangeOfOwnershipProperty(updatedMemberEntry.Value);
                        if (newCatalogZoneName is not null)
                        {
                            ApexZone catalogApexZone = _dnsServer.AuthZoneManager.GetApexZone(newCatalogZoneName);
                            if (catalogApexZone is SecondaryCatalogZone secondaryCatalogZone)
                            {
                                //found secondary catalog zone; transfer ownership to it
                                memberApexZone.CatalogZoneName = secondaryCatalogZone._name;
                            }
                            else
                            {
                                //no such secondary catalog zone exists; delete member zone
                                DeleteMemberZone(memberApexZone);
                                continue;
                            }
                        }
                    }

                    //allow query member zone custom property
                    {
                        IReadOnlyCollection<NetworkAccessControl> allowQueryACL = GetAllowQueryProperty(updatedMemberEntry.Value);
                        if (allowQueryACL.Count > 0)
                        {
                            memberApexZone.QueryAccess = GetQueryAccessType(allowQueryACL);

                            switch (memberApexZone.QueryAccess)
                            {
                                case AuthZoneQueryAccess.UseSpecifiedNetworkACL:
                                    memberApexZone.QueryAccessNetworkACL = allowQueryACL;
                                    break;

                                case AuthZoneQueryAccess.AllowZoneNameServersAndUseSpecifiedNetworkACL:
                                    memberApexZone.QueryAccessNetworkACL = GetFilteredACL(allowQueryACL);
                                    break;

                                default:
                                    memberApexZone.QueryAccessNetworkACL = null;
                                    break;
                            }

                            memberApexZone.OverrideCatalogQueryAccess = true;
                        }
                        else
                        {
                            memberApexZone.OverrideCatalogQueryAccess = false;
                            memberApexZone.QueryAccess = AuthZoneQueryAccess.Allow;
                            memberApexZone.QueryAccessNetworkACL = null;
                        }
                    }

                    if (memberApexZone is StubZone stubZone)
                    {
                        //primary addresses property
                        stubZone.PrimaryNameServerAddresses = GetPrimaryAddressesProperty(updatedMemberEntry.Value);
                    }
                    else if (memberApexZone is SecondaryForwarderZone)
                    {
                        //do nothing
                    }
                    else if (memberApexZone is SecondaryZone secondaryZone)
                    {
                        //primaries property
                        List<Tuple<IPAddress, string>> primaries = GetPrimariesProperty(updatedMemberEntry.Value);
                        if (primaries.Count == 0)
                            primaries = GetPrimariesProperty(_name);

                        if (primaries.Count > 0)
                        {
                            Tuple<IPAddress, string> primary = primaries[0];

                            secondaryZone.PrimaryNameServerAddresses = [new NameServerAddress(primary.Item1, DnsTransportProtocol.Tcp)];
                            secondaryZone.PrimaryZoneTransferProtocol = DnsTransportProtocol.Tcp;
                            secondaryZone.PrimaryZoneTransferTsigKeyName = primary.Item2;
                            secondaryZone.OverrideCatalogPrimaryNameServers = true;
                        }
                        else
                        {
                            secondaryZone.OverrideCatalogPrimaryNameServers = false;
                            secondaryZone.PrimaryNameServerAddresses = null;
                            secondaryZone.PrimaryZoneTransferProtocol = DnsTransportProtocol.Tcp;
                            secondaryZone.PrimaryZoneTransferTsigKeyName = null;
                        }

                        //allow transfer member zone custom property
                        IReadOnlyCollection<NetworkAccessControl> allowTransferACL = GetAllowTransferProperty(updatedMemberEntry.Value);
                        if (allowTransferACL.Count > 0)
                        {
                            memberApexZone.ZoneTransfer = GetZoneTransferType(allowTransferACL);

                            switch (memberApexZone.ZoneTransfer)
                            {
                                case AuthZoneTransfer.UseSpecifiedNetworkACL:
                                    memberApexZone.ZoneTransferNetworkACL = allowTransferACL;
                                    break;

                                case AuthZoneTransfer.AllowZoneNameServersAndUseSpecifiedNetworkACL:
                                    memberApexZone.ZoneTransferNetworkACL = GetFilteredACL(allowTransferACL);
                                    break;

                                default:
                                    memberApexZone.ZoneTransferNetworkACL = null;
                                    break;
                            }

                            //zone tranfer tsig key names member zone custom property
                            memberApexZone.ZoneTransferTsigKeyNames = GetZoneTransferTsigKeyNamesProperty(updatedMemberEntry.Value);

                            memberApexZone.OverrideCatalogZoneTransfer = true;
                        }
                        else
                        {
                            memberApexZone.OverrideCatalogZoneTransfer = false;
                            memberApexZone.ZoneTransfer = AuthZoneTransfer.Deny;
                            memberApexZone.ZoneTransferNetworkACL = null;
                            memberApexZone.ZoneTransferTsigKeyNames = null;
                        }
                    }

                    _dnsServer.AuthZoneManager.SaveZoneFile(memberApexZone.Name);
                }
            }
        }

        private void DeleteMemberZone(ApexZone apexZone)
        {
            AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);

            if (_dnsServer.AuthZoneManager.DeleteZone(zoneInfo, true))
            {
                ZoneRemoved?.Invoke(this, new SecondaryCatalogEventArgs(zoneInfo));

                _dnsServer.LogManager.Write(apexZone.GetZoneTypeName() + " zone '" + apexZone.ToString() + "' was removed via Secondary Catalog zone '" + ToString() + "' sucessfully.");
            }
        }

        private string GetVersion()
        {
            string domain = "version." + _name;

            IReadOnlyList<DnsResourceRecord> records = _dnsServer.AuthZoneManager.GetRecords(_name, domain, DnsResourceRecordType.TXT);
            if (records.Count > 0)
                return (records[0].RDATA as DnsTXTRecordData).GetText();

            return null;

        }

        private string GetChangeOfOwnershipProperty(string memberZoneDomain)
        {
            string domain = "coo." + memberZoneDomain;

            IReadOnlyList<DnsResourceRecord> records = _dnsServer.AuthZoneManager.GetRecords(_name, domain, DnsResourceRecordType.PTR);
            if (records.Count > 0)
                return (records[0].RDATA as DnsPTRRecordData).Domain;

            return null;
        }

        private AuthZoneType GetZoneTypeProperty(string memberZoneDomain)
        {
            string domain = "zone-type.ext." + memberZoneDomain;

            IReadOnlyList<DnsResourceRecord> records = _dnsServer.AuthZoneManager.GetRecords(_name, domain, DnsResourceRecordType.TXT);
            if (records.Count > 0)
                return Enum.Parse<AuthZoneType>((records[0].RDATA as DnsTXTRecordData).GetText(), true);

            return AuthZoneType.Primary;
        }

        private List<Tuple<IPAddress, string>> GetPrimariesProperty(string memberZoneDomain)
        {
            string domain = "primaries.ext." + memberZoneDomain;

            List<Tuple<IPAddress, string>> primaries = new List<Tuple<IPAddress, string>>(2);

            AuthZone authZone = _dnsServer.AuthZoneManager.GetAuthZone(_name, domain);
            if (authZone is not null)
            {
                foreach (DnsResourceRecord record in authZone.GetRecords(DnsResourceRecordType.A))
                    primaries.Add(new Tuple<IPAddress, string>((record.RDATA as DnsARecordData).Address, null));

                foreach (DnsResourceRecord record in authZone.GetRecords(DnsResourceRecordType.AAAA))
                    primaries.Add(new Tuple<IPAddress, string>((record.RDATA as DnsAAAARecordData).Address, null));
            }

            List<string> subdomains = new List<string>();
            _dnsServer.AuthZoneManager.ListSubDomains(domain, subdomains);

            foreach (string subdomain in subdomains)
            {
                AuthZone subZone = _dnsServer.AuthZoneManager.GetAuthZone(_name, subdomain + "." + domain);
                if (subZone is null)
                    continue;

                string tsigKeyName = null;
                IReadOnlyList<DnsResourceRecord> szTXTRecords = subZone.GetRecords(DnsResourceRecordType.TXT);
                if (szTXTRecords.Count > 0)
                    tsigKeyName = (szTXTRecords[0].RDATA as DnsTXTRecordData).GetText();

                foreach (DnsResourceRecord record in subZone.GetRecords(DnsResourceRecordType.A))
                    primaries.Add(new Tuple<IPAddress, string>((record.RDATA as DnsARecordData).Address, tsigKeyName));

                foreach (DnsResourceRecord record in subZone.GetRecords(DnsResourceRecordType.AAAA))
                    primaries.Add(new Tuple<IPAddress, string>((record.RDATA as DnsAAAARecordData).Address, tsigKeyName));
            }

            return primaries;
        }

        private IReadOnlyList<NameServerAddress> GetPrimaryAddressesProperty(string memberZoneDomain)
        {
            string domain = "primary-addresses.ext." + memberZoneDomain;

            IReadOnlyList<DnsResourceRecord> records = _dnsServer.AuthZoneManager.GetRecords(_name, domain, DnsResourceRecordType.TXT);
            if (records.Count > 0)
                return (records[0].RDATA as DnsTXTRecordData).CharacterStrings.Convert(NameServerAddress.Parse);

            return [];
        }

        private IReadOnlyCollection<NetworkAccessControl> GetAllowQueryProperty(string memberZoneDomain)
        {
            string domain = "allow-query.ext." + memberZoneDomain;

            IReadOnlyList<DnsResourceRecord> records = _dnsServer.AuthZoneManager.GetRecords(_name, domain, DnsResourceRecordType.APL);
            if (records.Count > 0)
                return NetworkAccessControl.ConvertFromAPLRecordData(records[0].RDATA as DnsAPLRecordData);

            return [];
        }

        private IReadOnlyCollection<NetworkAccessControl> GetAllowTransferProperty(string memberZoneDomain)
        {
            string domain = "allow-transfer.ext." + memberZoneDomain;

            IReadOnlyList<DnsResourceRecord> records = _dnsServer.AuthZoneManager.GetRecords(_name, domain, DnsResourceRecordType.APL);
            if (records.Count > 0)
                return NetworkAccessControl.ConvertFromAPLRecordData(records[0].RDATA as DnsAPLRecordData);

            return [];
        }

        private HashSet<string> GetZoneTransferTsigKeyNamesProperty(string memberZoneDomain)
        {
            string domain = "transfer-tsig-key-names.ext." + memberZoneDomain;

            IReadOnlyList<DnsResourceRecord> records = _dnsServer.AuthZoneManager.GetRecords(_name, domain, DnsResourceRecordType.PTR);
            HashSet<string> keyNames = new HashSet<string>(records.Count);

            foreach (DnsResourceRecord record in records)
                keyNames.Add((record.RDATA as DnsPTRRecordData).Domain.ToLowerInvariant());

            return keyNames;
        }

        private static AuthZoneQueryAccess GetQueryAccessType(IReadOnlyCollection<NetworkAccessControl> acl)
        {
            if (acl.HasSameItems(_allowACL))
                return AuthZoneQueryAccess.Allow;

            if (acl.HasSameItems(_queryAccessAllowOnlyPrivateNetworksACL))
                return AuthZoneQueryAccess.AllowOnlyPrivateNetworks;

            if (acl.HasSameItems(_allowOnlyZoneNameServersACL))
                return AuthZoneQueryAccess.AllowOnlyZoneNameServers;

            if ((acl.Count > 1) && acl.Contains(_allowZoneNameServersAndUseSpecifiedNetworkACL))
                return AuthZoneQueryAccess.AllowZoneNameServersAndUseSpecifiedNetworkACL;

            if (acl.HasSameItems(_denyACL))
                return AuthZoneQueryAccess.Deny;

            return AuthZoneQueryAccess.UseSpecifiedNetworkACL;
        }

        private static AuthZoneTransfer GetZoneTransferType(IReadOnlyCollection<NetworkAccessControl> acl)
        {
            if (acl.HasSameItems(_allowACL))
                return AuthZoneTransfer.Allow;

            if (acl.HasSameItems(_allowOnlyZoneNameServersACL))
                return AuthZoneTransfer.AllowOnlyZoneNameServers;

            if ((acl.Count > 1) && acl.Contains(_allowZoneNameServersAndUseSpecifiedNetworkACL))
                return AuthZoneTransfer.AllowZoneNameServersAndUseSpecifiedNetworkACL;

            if (acl.HasSameItems(_denyACL))
                return AuthZoneTransfer.Deny;

            return AuthZoneTransfer.UseSpecifiedNetworkACL;
        }

        private static List<NetworkAccessControl> GetFilteredACL(IReadOnlyCollection<NetworkAccessControl> acl)
        {
            List<NetworkAccessControl> filteredACL = new List<NetworkAccessControl>(acl.Count);

            foreach (NetworkAccessControl ac in acl)
            {
                if (ac.Equals(_allowZoneNameServersAndUseSpecifiedNetworkACL))
                    continue;

                filteredACL.Add(ac);
            }

            return filteredACL;
        }

        #endregion

        #region public

        public override string GetZoneTypeName()
        {
            return "Secondary Catalog";
        }

        public override IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type, bool dnssecOk)
        {
            return []; //secondary catalog zone is not queriable
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
            get { throw new InvalidOperationException(); }
            set { throw new InvalidOperationException(); }
        }

        public override AuthZoneQueryAccess QueryAccess
        {
            get { return _queryAccess; }
            set { throw new InvalidOperationException(); }
        }

        public override AuthZoneTransfer ZoneTransfer
        {
            get { return _zoneTransfer; }
            set { throw new InvalidOperationException(); }
        }

        public override AuthZoneUpdate Update
        {
            get { return base.Update; }
            set { throw new InvalidOperationException(); }
        }

        #endregion
    }

    public class SecondaryCatalogEventArgs : EventArgs
    {
        #region variables

        readonly AuthZoneInfo _zoneInfo;

        #endregion

        #region constructor

        public SecondaryCatalogEventArgs(AuthZoneInfo zoneInfo)
        {
            _zoneInfo = zoneInfo;
        }

        #endregion

        #region properties

        public AuthZoneInfo ZoneInfo
        { get { return _zoneInfo; } }

        #endregion
    }
}
