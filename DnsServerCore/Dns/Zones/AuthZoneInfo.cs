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
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    public enum AuthZoneType : byte
    {
        Unknown = 0,
        Primary = 1,
        Secondary = 2,
        Stub = 3,
        Forwarder = 4,
        SecondaryForwarder = 5,
        Catalog = 6,
        SecondaryCatalog = 7
    }

    public sealed class AuthZoneInfo : IComparable<AuthZoneInfo>
    {
        #region variables

        readonly ApexZone _apexZone;

        readonly string _name;
        readonly AuthZoneType _type;
        readonly DateTime _lastModified;
        readonly bool _disabled;

        readonly string _catalogZoneName;
        readonly bool _overrideCatalogQueryAccess;
        readonly bool _overrideCatalogZoneTransfer;
        readonly bool _overrideCatalogNotify;
        readonly bool _overrideCatalogPrimaryNameServers; //only for secondary zones

        readonly AuthZoneQueryAccess _queryAccess;
        readonly IReadOnlyCollection<NetworkAccessControl> _queryAccessNetworkACL;

        readonly AuthZoneTransfer _zoneTransfer;
        readonly IReadOnlyCollection<NetworkAccessControl> _zoneTransferNetworkACL;
        readonly IReadOnlySet<string> _zoneTransferTsigKeyNames;
        readonly IReadOnlyList<DnsResourceRecord> _zoneHistory; //for IXFR support

        readonly AuthZoneNotify _notify;
        readonly IReadOnlyCollection<IPAddress> _notifyNameServers;
        readonly IReadOnlyCollection<IPAddress> _notifySecondaryCatalogNameServers;

        readonly AuthZoneUpdate _update;
        readonly IReadOnlyCollection<NetworkAccessControl> _updateNetworkACL;
        readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>> _updateSecurityPolicies;

        readonly IReadOnlyCollection<DnssecPrivateKey> _dnssecPrivateKeys; //only for primary zones

        readonly IReadOnlyList<NameServerAddress> _primaryNameServerAddresses; //only for secondary and stub zones
        readonly DnsTransportProtocol _primaryZoneTransferProtocol; //only for secondary zones
        readonly string _primaryZoneTransferTsigKeyName; //only for secondary zones

        readonly DateTime _expiry; //only for secondary and stub zones

        readonly bool _validateZone; //only for secondary zones
        readonly bool _validationFailed; //only for secondary zones

        #endregion

        #region constructor

        public AuthZoneInfo(string name, AuthZoneType type, bool disabled)
        {
            _name = name;
            _type = type;
            _lastModified = DateTime.UtcNow;
            _disabled = disabled;
            _queryAccess = AuthZoneQueryAccess.Allow;

            switch (_type)
            {
                case AuthZoneType.Primary:
                    _zoneTransfer = AuthZoneTransfer.AllowOnlyZoneNameServers;
                    _notify = AuthZoneNotify.ZoneNameServers;
                    _update = AuthZoneUpdate.Deny;
                    break;

                default:
                    _zoneTransfer = AuthZoneTransfer.Deny;
                    _notify = AuthZoneNotify.None;
                    _update = AuthZoneUpdate.Deny;
                    break;
            }
        }

        public AuthZoneInfo(BinaryReader bR, DateTime lastModified)
        {
            byte version = bR.ReadByte();
            switch (version)
            {
                case 1:
                case 2:
                case 3:
                case 4:
                case 5:
                case 6:
                case 7:
                case 8:
                case 9:
                case 10:
                case 11:
                    {
                        _name = bR.ReadShortString();
                        _type = (AuthZoneType)bR.ReadByte();
                        _disabled = bR.ReadBoolean();

                        _queryAccess = AuthZoneQueryAccess.Allow;

                        if (version >= 2)
                        {
                            {
                                _zoneTransfer = (AuthZoneTransfer)bR.ReadByte();

                                int count = bR.ReadByte();
                                if (count > 0)
                                {
                                    NetworkAddress[] networks = new NetworkAddress[count];

                                    if (version >= 9)
                                    {
                                        for (int i = 0; i < count; i++)
                                            networks[i] = NetworkAddress.ReadFrom(bR);
                                    }
                                    else
                                    {
                                        for (int i = 0; i < count; i++)
                                        {
                                            IPAddress address = IPAddressExtensions.ReadFrom(bR);

                                            switch (address.AddressFamily)
                                            {
                                                case AddressFamily.InterNetwork:
                                                    networks[i] = new NetworkAddress(address, 32);
                                                    break;

                                                case AddressFamily.InterNetworkV6:
                                                    networks[i] = new NetworkAddress(address, 128);
                                                    break;

                                                default:
                                                    throw new InvalidOperationException();
                                            }
                                        }
                                    }

                                    _zoneTransferNetworkACL = ConvertDenyAllowToACL(null, networks);
                                }
                            }

                            {
                                _notify = (AuthZoneNotify)bR.ReadByte();

                                int count = bR.ReadByte();
                                if (count > 0)
                                {
                                    IPAddress[] nameServers = new IPAddress[count];

                                    for (int i = 0; i < count; i++)
                                        nameServers[i] = IPAddressExtensions.ReadFrom(bR);

                                    _notifyNameServers = nameServers;
                                }
                            }

                            if (version >= 6)
                            {
                                _update = (AuthZoneUpdate)bR.ReadByte();

                                int count = bR.ReadByte();
                                if (count > 0)
                                {
                                    NetworkAddress[] networks = new NetworkAddress[count];

                                    if (version >= 9)
                                    {
                                        for (int i = 0; i < count; i++)
                                            networks[i] = NetworkAddress.ReadFrom(bR);
                                    }
                                    else
                                    {
                                        for (int i = 0; i < count; i++)
                                        {
                                            IPAddress address = IPAddressExtensions.ReadFrom(bR);

                                            switch (address.AddressFamily)
                                            {
                                                case AddressFamily.InterNetwork:
                                                    networks[i] = new NetworkAddress(address, 32);
                                                    break;

                                                case AddressFamily.InterNetworkV6:
                                                    networks[i] = new NetworkAddress(address, 128);
                                                    break;

                                                default:
                                                    throw new InvalidOperationException();
                                            }
                                        }
                                    }

                                    _updateNetworkACL = ConvertDenyAllowToACL(null, networks);
                                }
                            }
                        }
                        else
                        {
                            switch (_type)
                            {
                                case AuthZoneType.Primary:
                                    _zoneTransfer = AuthZoneTransfer.AllowOnlyZoneNameServers;
                                    _notify = AuthZoneNotify.ZoneNameServers;
                                    _update = AuthZoneUpdate.Deny;
                                    break;

                                default:
                                    _zoneTransfer = AuthZoneTransfer.Deny;
                                    _notify = AuthZoneNotify.None;
                                    _update = AuthZoneUpdate.Deny;
                                    break;
                            }
                        }

                        if (version >= 8)
                            _lastModified = bR.ReadDateTime();
                        else
                            _lastModified = lastModified;

                        switch (_type)
                        {
                            case AuthZoneType.Primary:
                                {
                                    if (version >= 3)
                                    {
                                        int count = bR.ReadInt32();
                                        DnsResourceRecord[] zoneHistory = new DnsResourceRecord[count];

                                        if (version >= 11)
                                        {
                                            for (int i = 0; i < count; i++)
                                            {
                                                zoneHistory[i] = new DnsResourceRecord(bR.BaseStream);

                                                if (bR.ReadBoolean())
                                                    zoneHistory[i].Tag = new HistoryRecordInfo(bR);
                                            }
                                        }
                                        else
                                        {
                                            for (int i = 0; i < count; i++)
                                            {
                                                zoneHistory[i] = new DnsResourceRecord(bR.BaseStream);
                                                zoneHistory[i].Tag = new HistoryRecordInfo(bR);
                                            }
                                        }

                                        _zoneHistory = zoneHistory;
                                    }

                                    if (version >= 4)
                                    {
                                        int count = bR.ReadByte();
                                        HashSet<string> tsigKeyNames = new HashSet<string>(count);

                                        for (int i = 0; i < count; i++)
                                            tsigKeyNames.Add(bR.ReadShortString());

                                        _zoneTransferTsigKeyNames = tsigKeyNames;
                                    }

                                    if (version >= 7)
                                    {
                                        int count = bR.ReadByte();
                                        Dictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>> updateSecurityPolicies = new Dictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>>(count);

                                        for (int i = 0; i < count; i++)
                                        {
                                            string tsigKeyName = bR.ReadShortString().ToLowerInvariant();

                                            if (!updateSecurityPolicies.TryGetValue(tsigKeyName, out IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>> policyMap))
                                            {
                                                policyMap = new Dictionary<string, IReadOnlyList<DnsResourceRecordType>>();
                                                updateSecurityPolicies.Add(tsigKeyName, policyMap);
                                            }

                                            int policyCount = bR.ReadByte();

                                            for (int j = 0; j < policyCount; j++)
                                            {
                                                string domain = bR.ReadShortString().ToLowerInvariant();

                                                if (!policyMap.TryGetValue(domain, out IReadOnlyList<DnsResourceRecordType> types))
                                                {
                                                    types = new List<DnsResourceRecordType>();
                                                    (policyMap as Dictionary<string, IReadOnlyList<DnsResourceRecordType>>).Add(domain, types);
                                                }

                                                int typeCount = bR.ReadByte();

                                                for (int k = 0; k < typeCount; k++)
                                                    (types as List<DnsResourceRecordType>).Add((DnsResourceRecordType)bR.ReadUInt16());
                                            }
                                        }

                                        _updateSecurityPolicies = updateSecurityPolicies;
                                    }
                                    else if (version >= 6)
                                    {
                                        int count = bR.ReadByte();
                                        Dictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>> updateSecurityPolicies = new Dictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>>(count);

                                        Dictionary<string, IReadOnlyList<DnsResourceRecordType>> defaultAllowPolicy = new Dictionary<string, IReadOnlyList<DnsResourceRecordType>>(1);
                                        defaultAllowPolicy.Add(_name, new List<DnsResourceRecordType>() { DnsResourceRecordType.ANY });
                                        defaultAllowPolicy.Add("*." + _name, new List<DnsResourceRecordType>() { DnsResourceRecordType.ANY });

                                        for (int i = 0; i < count; i++)
                                            updateSecurityPolicies.Add(bR.ReadShortString().ToLowerInvariant(), defaultAllowPolicy);

                                        _updateSecurityPolicies = updateSecurityPolicies;
                                    }

                                    if (version >= 5)
                                    {
                                        int count = bR.ReadByte();
                                        if (count > 0)
                                        {
                                            List<DnssecPrivateKey> dnssecPrivateKeys = new List<DnssecPrivateKey>(count);

                                            for (int i = 0; i < count; i++)
                                                dnssecPrivateKeys.Add(DnssecPrivateKey.ReadFrom(bR));

                                            _dnssecPrivateKeys = dnssecPrivateKeys;
                                        }
                                    }
                                }
                                break;

                            case AuthZoneType.Secondary:
                                {
                                    _expiry = bR.ReadDateTime();

                                    if (version >= 4)
                                    {
                                        int count = bR.ReadInt32();
                                        DnsResourceRecord[] zoneHistory = new DnsResourceRecord[count];

                                        if (version >= 11)
                                        {
                                            for (int i = 0; i < count; i++)
                                            {
                                                zoneHistory[i] = new DnsResourceRecord(bR.BaseStream);

                                                if (bR.ReadBoolean())
                                                    zoneHistory[i].Tag = new HistoryRecordInfo(bR);
                                            }
                                        }
                                        else
                                        {
                                            for (int i = 0; i < count; i++)
                                            {
                                                zoneHistory[i] = new DnsResourceRecord(bR.BaseStream);
                                                zoneHistory[i].Tag = new HistoryRecordInfo(bR);
                                            }
                                        }

                                        _zoneHistory = zoneHistory;
                                    }

                                    if (version >= 4)
                                    {
                                        int count = bR.ReadByte();
                                        HashSet<string> tsigKeyNames = new HashSet<string>(count);

                                        for (int i = 0; i < count; i++)
                                            tsigKeyNames.Add(bR.ReadShortString());

                                        _zoneTransferTsigKeyNames = tsigKeyNames;
                                    }

                                    if (version == 6)
                                    {
                                        //MUST skip old version data
                                        int count = bR.ReadByte();
                                        Dictionary<string, object> tsigKeyNames = new Dictionary<string, object>(count);

                                        for (int i = 0; i < count; i++)
                                            tsigKeyNames.Add(bR.ReadShortString(), null);
                                    }
                                }
                                break;

                            case AuthZoneType.Stub:
                                {
                                    _expiry = bR.ReadDateTime();
                                }
                                break;

                            case AuthZoneType.Forwarder:
                                {
                                    if (version >= 10)
                                    {
                                        int count = bR.ReadByte();
                                        Dictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>> updateSecurityPolicies = new Dictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>>(count);

                                        for (int i = 0; i < count; i++)
                                        {
                                            string tsigKeyName = bR.ReadShortString().ToLowerInvariant();

                                            if (!updateSecurityPolicies.TryGetValue(tsigKeyName, out IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>> policyMap))
                                            {
                                                policyMap = new Dictionary<string, IReadOnlyList<DnsResourceRecordType>>();
                                                updateSecurityPolicies.Add(tsigKeyName, policyMap);
                                            }

                                            int policyCount = bR.ReadByte();

                                            for (int j = 0; j < policyCount; j++)
                                            {
                                                string domain = bR.ReadShortString().ToLowerInvariant();

                                                if (!policyMap.TryGetValue(domain, out IReadOnlyList<DnsResourceRecordType> types))
                                                {
                                                    types = new List<DnsResourceRecordType>();
                                                    (policyMap as Dictionary<string, IReadOnlyList<DnsResourceRecordType>>).Add(domain, types);
                                                }

                                                int typeCount = bR.ReadByte();

                                                for (int k = 0; k < typeCount; k++)
                                                    (types as List<DnsResourceRecordType>).Add((DnsResourceRecordType)bR.ReadUInt16());
                                            }
                                        }

                                        _updateSecurityPolicies = updateSecurityPolicies;
                                    }
                                }
                                break;
                        }
                    }
                    break;

                case 12:
                case 13:
                case 14:
                    {
                        _name = bR.ReadShortString();
                        _type = (AuthZoneType)bR.ReadByte();
                        _lastModified = bR.ReadDateTime();
                        _disabled = bR.ReadBoolean();

                        switch (_type)
                        {
                            case AuthZoneType.Primary:
                                _catalogZoneName = bR.ReadShortString();
                                if (_catalogZoneName.Length == 0)
                                    _catalogZoneName = null;

                                _overrideCatalogQueryAccess = bR.ReadBoolean();
                                _overrideCatalogZoneTransfer = bR.ReadBoolean();
                                _overrideCatalogNotify = bR.ReadBoolean();

                                _queryAccess = (AuthZoneQueryAccess)bR.ReadByte();
                                _queryAccessNetworkACL = ReadNetworkACLFrom(bR);

                                _zoneTransfer = (AuthZoneTransfer)bR.ReadByte();
                                _zoneTransferNetworkACL = ReadNetworkACLFrom(bR);
                                _zoneTransferTsigKeyNames = ReadZoneTransferTsigKeyNamesFrom(bR);
                                _zoneHistory = ReadZoneHistoryFrom(bR);

                                _notify = (AuthZoneNotify)bR.ReadByte();
                                _notifyNameServers = ReadIPAddressesFrom(bR);

                                _update = (AuthZoneUpdate)bR.ReadByte();
                                _updateNetworkACL = ReadNetworkACLFrom(bR);
                                _updateSecurityPolicies = ReadUpdateSecurityPoliciesFrom(bR);

                                _dnssecPrivateKeys = ReadDnssecPrivateKeysFrom(bR);
                                break;

                            case AuthZoneType.Secondary:
                                _catalogZoneName = bR.ReadShortString();
                                if (_catalogZoneName.Length == 0)
                                    _catalogZoneName = null;

                                _overrideCatalogQueryAccess = bR.ReadBoolean();
                                _overrideCatalogZoneTransfer = bR.ReadBoolean();
                                _overrideCatalogPrimaryNameServers = bR.ReadBoolean();

                                _queryAccess = (AuthZoneQueryAccess)bR.ReadByte();
                                _queryAccessNetworkACL = ReadNetworkACLFrom(bR);

                                _zoneTransfer = (AuthZoneTransfer)bR.ReadByte();
                                _zoneTransferNetworkACL = ReadNetworkACLFrom(bR);
                                _zoneTransferTsigKeyNames = ReadZoneTransferTsigKeyNamesFrom(bR);
                                _zoneHistory = ReadZoneHistoryFrom(bR);

                                _notify = (AuthZoneNotify)bR.ReadByte();
                                _notifyNameServers = ReadIPAddressesFrom(bR);

                                _update = (AuthZoneUpdate)bR.ReadByte();
                                _updateNetworkACL = ReadNetworkACLFrom(bR);

                                if (version >= 14)
                                    _dnssecPrivateKeys = ReadDnssecPrivateKeysFrom(bR);

                                _primaryNameServerAddresses = ReadNameServerAddressesFrom(bR);
                                _primaryZoneTransferProtocol = (DnsTransportProtocol)bR.ReadByte();
                                _primaryZoneTransferTsigKeyName = bR.ReadShortString();
                                if (_primaryZoneTransferTsigKeyName.Length == 0)
                                    _primaryZoneTransferTsigKeyName = null;

                                _expiry = bR.ReadDateTime();
                                _validateZone = bR.ReadBoolean();
                                _validationFailed = bR.ReadBoolean();
                                break;

                            case AuthZoneType.Stub:
                                _catalogZoneName = bR.ReadShortString();
                                if (_catalogZoneName.Length == 0)
                                    _catalogZoneName = null;

                                _overrideCatalogQueryAccess = bR.ReadBoolean();

                                _queryAccess = (AuthZoneQueryAccess)bR.ReadByte();
                                _queryAccessNetworkACL = ReadNetworkACLFrom(bR);

                                _primaryNameServerAddresses = ReadNameServerAddressesFrom(bR);

                                _expiry = bR.ReadDateTime();
                                break;

                            case AuthZoneType.Forwarder:
                                _catalogZoneName = bR.ReadShortString();
                                if (_catalogZoneName.Length == 0)
                                    _catalogZoneName = null;

                                _overrideCatalogQueryAccess = bR.ReadBoolean();
                                _overrideCatalogZoneTransfer = bR.ReadBoolean();
                                _overrideCatalogNotify = bR.ReadBoolean();

                                _queryAccess = (AuthZoneQueryAccess)bR.ReadByte();
                                _queryAccessNetworkACL = ReadNetworkACLFrom(bR);

                                _zoneTransfer = (AuthZoneTransfer)bR.ReadByte();
                                _zoneTransferNetworkACL = ReadNetworkACLFrom(bR);
                                _zoneTransferTsigKeyNames = ReadZoneTransferTsigKeyNamesFrom(bR);
                                _zoneHistory = ReadZoneHistoryFrom(bR);

                                _notify = (AuthZoneNotify)bR.ReadByte();
                                _notifyNameServers = ReadIPAddressesFrom(bR);

                                _update = (AuthZoneUpdate)bR.ReadByte();
                                _updateNetworkACL = ReadNetworkACLFrom(bR);
                                _updateSecurityPolicies = ReadUpdateSecurityPoliciesFrom(bR);
                                break;

                            case AuthZoneType.SecondaryForwarder:
                                _catalogZoneName = bR.ReadShortString();
                                if (_catalogZoneName.Length == 0)
                                    _catalogZoneName = null;

                                _overrideCatalogQueryAccess = bR.ReadBoolean();

                                _queryAccess = (AuthZoneQueryAccess)bR.ReadByte();
                                _queryAccessNetworkACL = ReadNetworkACLFrom(bR);

                                _update = (AuthZoneUpdate)bR.ReadByte();
                                _updateNetworkACL = ReadNetworkACLFrom(bR);

                                _primaryNameServerAddresses = ReadNameServerAddressesFrom(bR);
                                _primaryZoneTransferProtocol = (DnsTransportProtocol)bR.ReadByte();
                                _primaryZoneTransferTsigKeyName = bR.ReadShortString();
                                if (_primaryZoneTransferTsigKeyName.Length == 0)
                                    _primaryZoneTransferTsigKeyName = null;

                                _expiry = bR.ReadDateTime();
                                break;

                            case AuthZoneType.Catalog:
                                _queryAccess = (AuthZoneQueryAccess)bR.ReadByte();
                                _queryAccessNetworkACL = ReadNetworkACLFrom(bR);

                                _zoneTransfer = (AuthZoneTransfer)bR.ReadByte();
                                _zoneTransferNetworkACL = ReadNetworkACLFrom(bR);
                                _zoneTransferTsigKeyNames = ReadZoneTransferTsigKeyNamesFrom(bR);
                                _zoneHistory = ReadZoneHistoryFrom(bR);

                                _notify = (AuthZoneNotify)bR.ReadByte();
                                _notifyNameServers = ReadIPAddressesFrom(bR);

                                if (version >= 13)
                                    _notifySecondaryCatalogNameServers = ReadIPAddressesFrom(bR);

                                break;

                            case AuthZoneType.SecondaryCatalog:
                                _queryAccess = (AuthZoneQueryAccess)bR.ReadByte();
                                _queryAccessNetworkACL = ReadNetworkACLFrom(bR);

                                _zoneTransfer = (AuthZoneTransfer)bR.ReadByte();
                                _zoneTransferNetworkACL = ReadNetworkACLFrom(bR);
                                _zoneTransferTsigKeyNames = ReadZoneTransferTsigKeyNamesFrom(bR);

                                _primaryNameServerAddresses = ReadNameServerAddressesFrom(bR);
                                _primaryZoneTransferProtocol = (DnsTransportProtocol)bR.ReadByte();
                                _primaryZoneTransferTsigKeyName = bR.ReadShortString();
                                if (_primaryZoneTransferTsigKeyName.Length == 0)
                                    _primaryZoneTransferTsigKeyName = null;

                                _expiry = bR.ReadDateTime();
                                break;
                        }
                    }
                    break;

                default:
                    throw new InvalidDataException("AuthZoneInfo format version not supported.");
            }
        }

        internal AuthZoneInfo(ApexZone apexZone, bool loadHistory = false)
        {
            _apexZone = apexZone;
            _name = _apexZone.Name;
            _lastModified = _apexZone.LastModified;
            _disabled = _apexZone.Disabled;

            if (_apexZone is PrimaryZone primaryZone)
            {
                _type = AuthZoneType.Primary;

                _catalogZoneName = _apexZone.CatalogZoneName;
                _overrideCatalogQueryAccess = _apexZone.OverrideCatalogQueryAccess;
                _overrideCatalogZoneTransfer = _apexZone.OverrideCatalogZoneTransfer;
                _overrideCatalogNotify = _apexZone.OverrideCatalogNotify;

                _queryAccess = _apexZone.QueryAccess;
                _queryAccessNetworkACL = _apexZone.QueryAccessNetworkACL;

                _zoneTransfer = _apexZone.ZoneTransfer;
                _zoneTransferNetworkACL = _apexZone.ZoneTransferNetworkACL;
                _zoneTransferTsigKeyNames = _apexZone.ZoneTransferTsigKeyNames;

                if (loadHistory)
                    _zoneHistory = _apexZone.GetZoneHistory();

                _notify = _apexZone.Notify;
                _notifyNameServers = _apexZone.NotifyNameServers;

                _update = _apexZone.Update;
                _updateNetworkACL = _apexZone.UpdateNetworkACL;
                _updateSecurityPolicies = _apexZone.UpdateSecurityPolicies;

                _dnssecPrivateKeys = primaryZone.DnssecPrivateKeys;
            }
            else if (_apexZone is SecondaryCatalogZone secondaryCatalogZone)
            {
                _type = AuthZoneType.SecondaryCatalog;

                _queryAccess = _apexZone.QueryAccess;
                _queryAccessNetworkACL = _apexZone.QueryAccessNetworkACL;

                _zoneTransfer = _apexZone.ZoneTransfer;
                _zoneTransferNetworkACL = _apexZone.ZoneTransferNetworkACL;
                _zoneTransferTsigKeyNames = _apexZone.ZoneTransferTsigKeyNames;

                _primaryNameServerAddresses = secondaryCatalogZone.PrimaryNameServerAddresses;
                _primaryZoneTransferProtocol = secondaryCatalogZone.PrimaryZoneTransferProtocol;
                _primaryZoneTransferTsigKeyName = secondaryCatalogZone.PrimaryZoneTransferTsigKeyName;

                _expiry = secondaryCatalogZone.Expiry;
            }
            else if (_apexZone is SecondaryForwarderZone secondaryForwarderZone)
            {
                _type = AuthZoneType.SecondaryForwarder;

                _catalogZoneName = _apexZone.CatalogZoneName;
                _overrideCatalogQueryAccess = _apexZone.OverrideCatalogQueryAccess;

                _queryAccess = _apexZone.QueryAccess;
                _queryAccessNetworkACL = _apexZone.QueryAccessNetworkACL;

                _update = _apexZone.Update;
                _updateNetworkACL = _apexZone.UpdateNetworkACL;

                _primaryNameServerAddresses = secondaryForwarderZone.PrimaryNameServerAddresses;
                _primaryZoneTransferProtocol = secondaryForwarderZone.PrimaryZoneTransferProtocol;
                _primaryZoneTransferTsigKeyName = secondaryForwarderZone.PrimaryZoneTransferTsigKeyName;

                _expiry = secondaryForwarderZone.Expiry;
            }
            else if (_apexZone is SecondaryZone secondaryZone)
            {
                _type = AuthZoneType.Secondary;

                _catalogZoneName = _apexZone.CatalogZoneName;
                _overrideCatalogQueryAccess = _apexZone.OverrideCatalogQueryAccess;
                _overrideCatalogZoneTransfer = _apexZone.OverrideCatalogZoneTransfer;
                _overrideCatalogPrimaryNameServers = secondaryZone.OverrideCatalogPrimaryNameServers;

                _queryAccess = _apexZone.QueryAccess;
                _queryAccessNetworkACL = _apexZone.QueryAccessNetworkACL;

                _zoneTransfer = _apexZone.ZoneTransfer;
                _zoneTransferNetworkACL = _apexZone.ZoneTransferNetworkACL;
                _zoneTransferTsigKeyNames = _apexZone.ZoneTransferTsigKeyNames;

                if (loadHistory)
                    _zoneHistory = _apexZone.GetZoneHistory();

                _notify = _apexZone.Notify;
                _notifyNameServers = _apexZone.NotifyNameServers;

                _update = _apexZone.Update;
                _updateNetworkACL = _apexZone.UpdateNetworkACL;

                _dnssecPrivateKeys = secondaryZone.DnssecPrivateKeys;

                _primaryNameServerAddresses = secondaryZone.PrimaryNameServerAddresses;
                _primaryZoneTransferProtocol = secondaryZone.PrimaryZoneTransferProtocol;
                _primaryZoneTransferTsigKeyName = secondaryZone.PrimaryZoneTransferTsigKeyName;

                _expiry = secondaryZone.Expiry;
                _validateZone = secondaryZone.ValidateZone;
                _validationFailed = secondaryZone.ValidationFailed;
            }
            else if (_apexZone is StubZone stubZone)
            {
                _type = AuthZoneType.Stub;

                _catalogZoneName = _apexZone.CatalogZoneName;
                _overrideCatalogQueryAccess = _apexZone.OverrideCatalogQueryAccess;

                _queryAccess = _apexZone.QueryAccess;
                _queryAccessNetworkACL = _apexZone.QueryAccessNetworkACL;

                _primaryNameServerAddresses = stubZone.PrimaryNameServerAddresses;

                _expiry = stubZone.Expiry;
            }
            else if (_apexZone is CatalogZone)
            {
                _type = AuthZoneType.Catalog;

                _queryAccess = _apexZone.QueryAccess;
                _queryAccessNetworkACL = _apexZone.QueryAccessNetworkACL;

                _zoneTransfer = _apexZone.ZoneTransfer;
                _zoneTransferNetworkACL = _apexZone.ZoneTransferNetworkACL;
                _zoneTransferTsigKeyNames = _apexZone.ZoneTransferTsigKeyNames;

                if (loadHistory)
                    _zoneHistory = _apexZone.GetZoneHistory();

                _notify = _apexZone.Notify;
                _notifyNameServers = _apexZone.NotifyNameServers;
                _notifySecondaryCatalogNameServers = _apexZone.NotifySecondaryCatalogNameServers;
            }
            else if (_apexZone is ForwarderZone)
            {
                _type = AuthZoneType.Forwarder;

                _catalogZoneName = _apexZone.CatalogZoneName;
                _overrideCatalogQueryAccess = _apexZone.OverrideCatalogQueryAccess;
                _overrideCatalogZoneTransfer = _apexZone.OverrideCatalogZoneTransfer;
                _overrideCatalogNotify = _apexZone.OverrideCatalogNotify;

                _queryAccess = _apexZone.QueryAccess;
                _queryAccessNetworkACL = _apexZone.QueryAccessNetworkACL;

                _zoneTransfer = _apexZone.ZoneTransfer;
                _zoneTransferNetworkACL = _apexZone.ZoneTransferNetworkACL;
                _zoneTransferTsigKeyNames = _apexZone.ZoneTransferTsigKeyNames;

                if (loadHistory)
                    _zoneHistory = _apexZone.GetZoneHistory();

                _notify = _apexZone.Notify;
                _notifyNameServers = _apexZone.NotifyNameServers;

                _update = _apexZone.Update;
                _updateNetworkACL = _apexZone.UpdateNetworkACL;
                _updateSecurityPolicies = _apexZone.UpdateSecurityPolicies;
            }
            else
            {
                _type = AuthZoneType.Unknown;
            }
        }

        #endregion

        #region static

        public static string GetZoneTypeName(AuthZoneType type)
        {
            switch (type)
            {
                case AuthZoneType.SecondaryForwarder:
                    return "Secondary Forwarder";

                case AuthZoneType.SecondaryCatalog:
                    return "Secondary Catalog";

                default:
                    return type.ToString();
            }
        }

        internal static NameServerAddress[] ReadNameServerAddressesFrom(BinaryReader bR)
        {
            int count = bR.ReadByte();
            if (count < 1)
                return null;

            NameServerAddress[] nameServerAddresses = new NameServerAddress[count];

            for (int i = 0; i < count; i++)
                nameServerAddresses[i] = new NameServerAddress(bR);

            return nameServerAddresses;
        }

        internal static void WriteNameServerAddressesTo(IReadOnlyCollection<NameServerAddress> nameServerAddresses, BinaryWriter bW)
        {
            if (nameServerAddresses is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(nameServerAddresses.Count));

                foreach (NameServerAddress network in nameServerAddresses)
                    network.WriteTo(bW);
            }
        }

        internal static NetworkAccessControl[] ReadNetworkACLFrom(BinaryReader bR)
        {
            int count = bR.ReadByte();
            if (count < 1)
                return null;

            NetworkAccessControl[] acl = new NetworkAccessControl[count];

            for (int i = 0; i < count; i++)
                acl[i] = NetworkAccessControl.ReadFrom(bR);

            return acl;
        }

        internal static void WriteNetworkACLTo(IReadOnlyCollection<NetworkAccessControl> acl, BinaryWriter bW)
        {
            if (acl is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(acl.Count));

                foreach (NetworkAccessControl nac in acl)
                    nac.WriteTo(bW);
            }
        }

        internal static NetworkAddress[] ReadNetworkAddressesFrom(BinaryReader bR)
        {
            int count = bR.ReadByte();
            if (count < 1)
                return null;

            NetworkAddress[] networks = new NetworkAddress[count];

            for (int i = 0; i < count; i++)
                networks[i] = NetworkAddress.ReadFrom(bR);

            return networks;
        }

        internal static void WriteNetworkAddressesTo(IReadOnlyCollection<NetworkAddress> networkAddresses, BinaryWriter bW)
        {
            if (networkAddresses is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(networkAddresses.Count));

                foreach (NetworkAddress network in networkAddresses)
                    network.WriteTo(bW);
            }
        }

        internal static IPAddress[] ReadIPAddressesFrom(BinaryReader bR)
        {
            int count = bR.ReadByte();
            if (count < 1)
                return null;

            IPAddress[] ipAddresses = new IPAddress[count];

            for (int i = 0; i < count; i++)
                ipAddresses[i] = IPAddressExtensions.ReadFrom(bR);

            return ipAddresses;
        }

        internal static void WriteIPAddressesTo(IReadOnlyCollection<IPAddress> ipAddresses, BinaryWriter bW)
        {
            if (ipAddresses is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(ipAddresses.Count));

                foreach (IPAddress ipAddress in ipAddresses)
                    ipAddress.WriteTo(bW);
            }
        }

        internal static List<NetworkAccessControl> ConvertDenyAllowToACL(NetworkAddress[] deniedNetworks, NetworkAddress[] allowedNetworks)
        {
            List<NetworkAccessControl> acl = new List<NetworkAccessControl>();

            if (deniedNetworks is not null)
            {
                foreach (NetworkAddress network in deniedNetworks)
                    acl.Add(new NetworkAccessControl(network, true));
            }

            if (allowedNetworks is not null)
            {
                foreach (NetworkAddress network in allowedNetworks)
                    acl.Add(new NetworkAccessControl(network));
            }

            if (acl.Count > 0)
                return acl;

            return null;
        }

        private static HashSet<string> ReadZoneTransferTsigKeyNamesFrom(BinaryReader bR)
        {
            int count = bR.ReadByte();
            HashSet<string> zoneTransferTsigKeyNames = new HashSet<string>(count);

            for (int i = 0; i < count; i++)
                zoneTransferTsigKeyNames.Add(bR.ReadShortString());

            return zoneTransferTsigKeyNames;
        }

        private static void WriteZoneTransferTsigKeyNamesTo(IReadOnlySet<string> zoneTransferTsigKeyNames, BinaryWriter bW)
        {
            if (zoneTransferTsigKeyNames is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(zoneTransferTsigKeyNames.Count));

                foreach (string tsigKeyName in zoneTransferTsigKeyNames)
                    bW.WriteShortString(tsigKeyName);
            }
        }

        private static DnsResourceRecord[] ReadZoneHistoryFrom(BinaryReader bR)
        {
            int count = bR.ReadInt32();
            DnsResourceRecord[] zoneHistory = new DnsResourceRecord[count];

            for (int i = 0; i < count; i++)
            {
                zoneHistory[i] = new DnsResourceRecord(bR.BaseStream);

                if (bR.ReadBoolean())
                    zoneHistory[i].Tag = new HistoryRecordInfo(bR);
            }

            return zoneHistory;
        }

        private static void WriteZoneHistoryTo(IReadOnlyList<DnsResourceRecord> zoneHistory, BinaryWriter bW)
        {
            if (zoneHistory is null)
            {
                bW.Write(0);
            }
            else
            {
                bW.Write(zoneHistory.Count);

                foreach (DnsResourceRecord record in zoneHistory)
                {
                    record.WriteTo(bW.BaseStream);

                    if (record.Tag is HistoryRecordInfo rrInfo)
                    {
                        bW.Write(true);
                        rrInfo.WriteTo(bW);
                    }
                    else
                    {
                        bW.Write(false);
                    }
                }
            }
        }

        private static Dictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>> ReadUpdateSecurityPoliciesFrom(BinaryReader bR)
        {
            int count = bR.ReadInt32();
            Dictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>> updateSecurityPolicies = new Dictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>>(count);

            for (int i = 0; i < count; i++)
            {
                string tsigKeyName = bR.ReadShortString().ToLowerInvariant();

                if (!updateSecurityPolicies.TryGetValue(tsigKeyName, out IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>> policyMap))
                {
                    policyMap = new Dictionary<string, IReadOnlyList<DnsResourceRecordType>>();
                    updateSecurityPolicies.Add(tsigKeyName, policyMap);
                }

                int policyCount = bR.ReadByte();

                for (int j = 0; j < policyCount; j++)
                {
                    string domain = bR.ReadShortString().ToLowerInvariant();

                    if (!policyMap.TryGetValue(domain, out IReadOnlyList<DnsResourceRecordType> types))
                    {
                        types = new List<DnsResourceRecordType>();
                        (policyMap as Dictionary<string, IReadOnlyList<DnsResourceRecordType>>).Add(domain, types);
                    }

                    int typeCount = bR.ReadByte();

                    for (int k = 0; k < typeCount; k++)
                        (types as List<DnsResourceRecordType>).Add((DnsResourceRecordType)bR.ReadUInt16());
                }
            }

            return updateSecurityPolicies;
        }

        private static void WriteUpdateSecurityPoliciesTo(IReadOnlyDictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>> updateSecurityPolicies, BinaryWriter bW)
        {
            if (updateSecurityPolicies is null)
            {
                bW.Write(0);
            }
            else
            {
                bW.Write(updateSecurityPolicies.Count);

                foreach (KeyValuePair<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>> updateSecurityPolicy in updateSecurityPolicies)
                {
                    bW.WriteShortString(updateSecurityPolicy.Key);
                    bW.Write(Convert.ToByte(updateSecurityPolicy.Value.Count));

                    foreach (KeyValuePair<string, IReadOnlyList<DnsResourceRecordType>> policyMap in updateSecurityPolicy.Value)
                    {
                        bW.WriteShortString(policyMap.Key);
                        bW.Write(Convert.ToByte(policyMap.Value.Count));

                        foreach (DnsResourceRecordType type in policyMap.Value)
                            bW.Write((ushort)type);
                    }
                }
            }
        }

        internal static DnssecPrivateKey[] ReadDnssecPrivateKeysFrom(BinaryReader bR)
        {
            int count = bR.ReadByte();
            if (count < 1)
                return null;

            DnssecPrivateKey[] dnssecPrivateKeys = new DnssecPrivateKey[count];

            for (int i = 0; i < count; i++)
                dnssecPrivateKeys[i] = DnssecPrivateKey.ReadFrom(bR);

            return dnssecPrivateKeys;
        }

        internal static void WriteDnssecPrivateKeysTo(IReadOnlyCollection<DnssecPrivateKey> dnssecPrivateKeys, BinaryWriter bW)
        {
            if (dnssecPrivateKeys is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(dnssecPrivateKeys.Count));

                foreach (DnssecPrivateKey dnssecPrivateKey in dnssecPrivateKeys)
                    dnssecPrivateKey.WriteTo(bW);
            }
        }

        #endregion

        #region public

        public void TriggerRefresh()
        {
            if (_apexZone is null)
                throw new InvalidOperationException();

            switch (_type)
            {
                case AuthZoneType.Secondary:
                case AuthZoneType.SecondaryForwarder:
                case AuthZoneType.SecondaryCatalog:
                    (_apexZone as SecondaryZone).TriggerRefresh();
                    break;

                case AuthZoneType.Stub:
                    (_apexZone as StubZone).TriggerRefresh();
                    break;

                default:
                    throw new InvalidOperationException();
            }
        }

        public void TriggerResync()
        {
            if (_apexZone is null)
                throw new InvalidOperationException();

            switch (_type)
            {
                case AuthZoneType.Secondary:
                case AuthZoneType.SecondaryForwarder:
                case AuthZoneType.SecondaryCatalog:
                    (_apexZone as SecondaryZone).TriggerResync();
                    break;

                case AuthZoneType.Stub:
                    (_apexZone as StubZone).TriggerResync();
                    break;

                default:
                    throw new InvalidOperationException();
            }
        }

        public void WriteTo(BinaryWriter bW)
        {
            if (_apexZone is null)
                throw new InvalidOperationException();

            bW.Write((byte)14); //version

            bW.WriteShortString(_name);
            bW.Write((byte)_type);
            bW.Write(_lastModified);
            bW.Write(_disabled);

            switch (_type)
            {
                case AuthZoneType.Primary:
                    bW.Write(_catalogZoneName ?? "");
                    bW.Write(_overrideCatalogQueryAccess);
                    bW.Write(_overrideCatalogZoneTransfer);
                    bW.Write(_overrideCatalogNotify);

                    bW.Write((byte)_queryAccess);
                    WriteNetworkACLTo(_queryAccessNetworkACL, bW);

                    bW.Write((byte)_zoneTransfer);
                    WriteNetworkACLTo(_zoneTransferNetworkACL, bW);
                    WriteZoneTransferTsigKeyNamesTo(_zoneTransferTsigKeyNames, bW);
                    WriteZoneHistoryTo(_zoneHistory, bW);

                    bW.Write((byte)_notify);
                    WriteIPAddressesTo(_notifyNameServers, bW);

                    bW.Write((byte)_update);
                    WriteNetworkACLTo(_updateNetworkACL, bW);
                    WriteUpdateSecurityPoliciesTo(_updateSecurityPolicies, bW);

                    WriteDnssecPrivateKeysTo(_dnssecPrivateKeys, bW);
                    break;

                case AuthZoneType.Secondary:
                    bW.Write(_catalogZoneName ?? "");
                    bW.Write(_overrideCatalogQueryAccess);
                    bW.Write(_overrideCatalogZoneTransfer);
                    bW.Write(_overrideCatalogPrimaryNameServers);

                    bW.Write((byte)_queryAccess);
                    WriteNetworkACLTo(_queryAccessNetworkACL, bW);

                    bW.Write((byte)_zoneTransfer);
                    WriteNetworkACLTo(_zoneTransferNetworkACL, bW);
                    WriteZoneTransferTsigKeyNamesTo(_zoneTransferTsigKeyNames, bW);
                    WriteZoneHistoryTo(_zoneHistory, bW);

                    bW.Write((byte)_notify);
                    WriteIPAddressesTo(_notifyNameServers, bW);

                    bW.Write((byte)_update);
                    WriteNetworkACLTo(_updateNetworkACL, bW);

                    WriteDnssecPrivateKeysTo(_dnssecPrivateKeys, bW);

                    WriteNameServerAddressesTo(_primaryNameServerAddresses, bW);
                    bW.Write((byte)_primaryZoneTransferProtocol);
                    bW.Write(_primaryZoneTransferTsigKeyName ?? "");

                    bW.Write(_expiry);
                    bW.Write(_validateZone);
                    bW.Write(_validationFailed);
                    break;

                case AuthZoneType.Stub:
                    bW.Write(_catalogZoneName ?? "");
                    bW.Write(_overrideCatalogQueryAccess);

                    bW.Write((byte)_queryAccess);
                    WriteNetworkACLTo(_queryAccessNetworkACL, bW);

                    WriteNameServerAddressesTo(_primaryNameServerAddresses, bW);

                    bW.Write(_expiry);
                    break;

                case AuthZoneType.Forwarder:
                    bW.Write(_catalogZoneName ?? "");
                    bW.Write(_overrideCatalogQueryAccess);
                    bW.Write(_overrideCatalogZoneTransfer);
                    bW.Write(_overrideCatalogNotify);

                    bW.Write((byte)_queryAccess);
                    WriteNetworkACLTo(_queryAccessNetworkACL, bW);

                    bW.Write((byte)_zoneTransfer);
                    WriteNetworkACLTo(_zoneTransferNetworkACL, bW);
                    WriteZoneTransferTsigKeyNamesTo(_zoneTransferTsigKeyNames, bW);
                    WriteZoneHistoryTo(_zoneHistory, bW);

                    bW.Write((byte)_notify);
                    WriteIPAddressesTo(_notifyNameServers, bW);

                    bW.Write((byte)_update);
                    WriteNetworkACLTo(_updateNetworkACL, bW);
                    WriteUpdateSecurityPoliciesTo(_updateSecurityPolicies, bW);
                    break;

                case AuthZoneType.SecondaryForwarder:
                    bW.Write(_catalogZoneName ?? "");
                    bW.Write(_overrideCatalogQueryAccess);

                    bW.Write((byte)_queryAccess);
                    WriteNetworkACLTo(_queryAccessNetworkACL, bW);

                    bW.Write((byte)_update);
                    WriteNetworkACLTo(_updateNetworkACL, bW);

                    WriteNameServerAddressesTo(_primaryNameServerAddresses, bW);
                    bW.Write((byte)_primaryZoneTransferProtocol);
                    bW.Write(_primaryZoneTransferTsigKeyName ?? "");

                    bW.Write(_expiry);
                    break;

                case AuthZoneType.Catalog:
                    bW.Write((byte)_queryAccess);
                    WriteNetworkACLTo(_queryAccessNetworkACL, bW);

                    bW.Write((byte)_zoneTransfer);
                    WriteNetworkACLTo(_zoneTransferNetworkACL, bW);
                    WriteZoneTransferTsigKeyNamesTo(_zoneTransferTsigKeyNames, bW);
                    WriteZoneHistoryTo(_zoneHistory, bW);

                    bW.Write((byte)_notify);
                    WriteIPAddressesTo(_notifyNameServers, bW);
                    WriteIPAddressesTo(_notifySecondaryCatalogNameServers, bW);
                    break;

                case AuthZoneType.SecondaryCatalog:
                    bW.Write((byte)_queryAccess);
                    WriteNetworkACLTo(_queryAccessNetworkACL, bW);

                    bW.Write((byte)_zoneTransfer);
                    WriteNetworkACLTo(_zoneTransferNetworkACL, bW);
                    WriteZoneTransferTsigKeyNamesTo(_zoneTransferTsigKeyNames, bW);

                    WriteNameServerAddressesTo(_primaryNameServerAddresses, bW);
                    bW.Write((byte)_primaryZoneTransferProtocol);
                    bW.Write(_primaryZoneTransferTsigKeyName ?? "");

                    bW.Write(_expiry);
                    break;
            }
        }

        public int CompareTo(AuthZoneInfo other)
        {
            return _name.CompareTo(other._name);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(this, obj))
                return true;

            if (obj is not AuthZoneInfo other)
                return false;

            return _name.Equals(other._name, StringComparison.OrdinalIgnoreCase);
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_name);
        }

        public override string ToString()
        {
            return _name.Length == 0 ? "<root>" : _name; ;
        }

        #endregion

        #region properties

        internal ApexZone ApexZone
        { get { return _apexZone; } }

        public string Name
        { get { return _name; } }

        public string DisplayName
        { get { return _name.Length == 0 ? "<root>" : _name; } }

        public AuthZoneType Type
        { get { return _type; } }

        public string TypeName
        { get { return GetZoneTypeName(_type); } }

        public DateTime LastModified
        {
            get
            {
                if (_apexZone is null)
                    return _lastModified;

                return _apexZone.LastModified;
            }
        }

        public bool Disabled
        {
            get
            {
                if (_apexZone is null)
                    return _disabled;

                return _apexZone.Disabled;
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                _apexZone.Disabled = value;
            }
        }

        public string CatalogZoneName
        {
            get
            {
                if (_apexZone is null)
                    return _catalogZoneName;

                return _apexZone.CatalogZoneName;
            }
        }

        public bool OverrideCatalogQueryAccess
        {
            get
            {
                if (_apexZone is null)
                    return _overrideCatalogQueryAccess;

                return _apexZone.OverrideCatalogQueryAccess;
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                _apexZone.OverrideCatalogQueryAccess = value;
            }
        }

        public bool OverrideCatalogZoneTransfer
        {
            get
            {
                if (_apexZone is null)
                    return _overrideCatalogZoneTransfer;

                return _apexZone.OverrideCatalogZoneTransfer;
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                _apexZone.OverrideCatalogZoneTransfer = value;
            }
        }

        public bool OverrideCatalogNotify
        {
            get
            {
                if (_apexZone is null)
                    return _overrideCatalogNotify;

                return _apexZone.OverrideCatalogNotify;
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                _apexZone.OverrideCatalogNotify = value;
            }
        }

        public bool OverrideCatalogPrimaryNameServers
        {
            get
            {
                if (_apexZone is null)
                    return _overrideCatalogPrimaryNameServers;

                switch (_type)
                {
                    case AuthZoneType.Secondary:
                        return (_apexZone as SecondaryZone).OverrideCatalogPrimaryNameServers;

                    case AuthZoneType.SecondaryForwarder:
                    case AuthZoneType.SecondaryCatalog:
                        return false;

                    default:
                        throw new InvalidOperationException();
                }
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                switch (_type)
                {
                    case AuthZoneType.Secondary:
                        (_apexZone as SecondaryZone).OverrideCatalogPrimaryNameServers = value;
                        break;

                    default:
                        throw new InvalidOperationException();
                }
            }
        }

        public AuthZoneQueryAccess QueryAccess
        {
            get
            {
                if (_apexZone is null)
                    return _queryAccess;

                return _apexZone.QueryAccess;
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                _apexZone.QueryAccess = value;
            }
        }

        public IReadOnlyCollection<NetworkAccessControl> QueryAccessNetworkACL
        {
            get
            {
                if (_apexZone is null)
                    return _queryAccessNetworkACL;

                return _apexZone.QueryAccessNetworkACL;
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                _apexZone.QueryAccessNetworkACL = value;
            }
        }

        public AuthZoneTransfer ZoneTransfer
        {
            get
            {
                if (_apexZone is null)
                    return _zoneTransfer;

                return _apexZone.ZoneTransfer;
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                _apexZone.ZoneTransfer = value;
            }
        }

        public IReadOnlyCollection<NetworkAccessControl> ZoneTransferNetworkACL
        {
            get
            {
                if (_apexZone is null)
                    return _zoneTransferNetworkACL;

                return _apexZone.ZoneTransferNetworkACL;
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                _apexZone.ZoneTransferNetworkACL = value;
            }
        }

        public IReadOnlySet<string> ZoneTransferTsigKeyNames
        {
            get
            {
                if (_apexZone is null)
                    return _zoneTransferTsigKeyNames;

                return _apexZone.ZoneTransferTsigKeyNames;
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                switch (_type)
                {
                    case AuthZoneType.Primary:
                    case AuthZoneType.Secondary:
                    case AuthZoneType.Forwarder:
                    case AuthZoneType.Catalog:
                        _apexZone.ZoneTransferTsigKeyNames = value;
                        break;

                    default:
                        throw new InvalidOperationException();
                }
            }
        }

        public IReadOnlyList<DnsResourceRecord> ZoneHistory
        {
            get
            {
                if (_apexZone is null)
                    return _zoneHistory;

                return _apexZone.GetZoneHistory();
            }
        }

        public AuthZoneNotify Notify
        {
            get
            {
                if (_apexZone is null)
                    return _notify;

                return _apexZone.Notify;
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                _apexZone.Notify = value;
            }
        }

        public IReadOnlyCollection<IPAddress> NotifyNameServers
        {
            get
            {
                if (_apexZone is null)
                    return _notifyNameServers;

                return _apexZone.NotifyNameServers;
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                _apexZone.NotifyNameServers = value;
            }
        }

        public IReadOnlyCollection<IPAddress> NotifySecondaryCatalogNameServers
        {
            get
            {
                if (_apexZone is null)
                    return _notifySecondaryCatalogNameServers;

                return _apexZone.NotifySecondaryCatalogNameServers;
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                _apexZone.NotifySecondaryCatalogNameServers = value;
            }
        }

        public AuthZoneUpdate Update
        {
            get
            {
                if (_apexZone is null)
                    return _update;

                return _apexZone.Update;
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                _apexZone.Update = value;
            }
        }

        public IReadOnlyCollection<NetworkAccessControl> UpdateNetworkACL
        {
            get
            {
                if (_apexZone is null)
                    return _updateNetworkACL;

                return _apexZone.UpdateNetworkACL;
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                _apexZone.UpdateNetworkACL = value;
            }
        }

        public IReadOnlyDictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>> UpdateSecurityPolicies
        {
            get
            {
                if (_apexZone is null)
                    return _updateSecurityPolicies;

                return _apexZone.UpdateSecurityPolicies;
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                switch (_type)
                {
                    case AuthZoneType.Primary:
                    case AuthZoneType.Forwarder:
                        _apexZone.UpdateSecurityPolicies = value;
                        break;

                    default:
                        throw new InvalidOperationException();
                }
            }
        }

        public IReadOnlyCollection<DnssecPrivateKey> DnssecPrivateKeys
        {
            get
            {
                if (_apexZone is null)
                    return _dnssecPrivateKeys;

                switch (_type)
                {
                    case AuthZoneType.Primary:
                        return (_apexZone as PrimaryZone).DnssecPrivateKeys;

                    case AuthZoneType.Secondary:
                        return (_apexZone as SecondaryZone).DnssecPrivateKeys;

                    default:
                        throw new InvalidOperationException();
                }
            }
        }

        public IReadOnlyList<NameServerAddress> PrimaryNameServerAddresses
        {
            get
            {
                if (_apexZone is null)
                    return _primaryNameServerAddresses;

                switch (_type)
                {
                    case AuthZoneType.Secondary:
                    case AuthZoneType.SecondaryForwarder:
                    case AuthZoneType.SecondaryCatalog:
                        return (_apexZone as SecondaryZone).PrimaryNameServerAddresses;

                    case AuthZoneType.Stub:
                        return (_apexZone as StubZone).PrimaryNameServerAddresses;

                    default:
                        throw new InvalidOperationException();
                }
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                switch (_type)
                {
                    case AuthZoneType.Secondary:
                    case AuthZoneType.SecondaryForwarder:
                    case AuthZoneType.SecondaryCatalog:
                        (_apexZone as SecondaryZone).PrimaryNameServerAddresses = value;
                        break;

                    case AuthZoneType.Stub:
                        (_apexZone as StubZone).PrimaryNameServerAddresses = value;
                        break;

                    default:
                        throw new InvalidOperationException();
                }
            }
        }

        public DnsTransportProtocol PrimaryZoneTransferProtocol
        {
            get
            {
                if (_apexZone is null)
                    return _primaryZoneTransferProtocol;

                switch (_type)
                {
                    case AuthZoneType.Secondary:
                    case AuthZoneType.SecondaryForwarder:
                    case AuthZoneType.SecondaryCatalog:
                        return (_apexZone as SecondaryZone).PrimaryZoneTransferProtocol;

                    default:
                        throw new InvalidOperationException();
                }
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                switch (_type)
                {
                    case AuthZoneType.Secondary:
                    case AuthZoneType.SecondaryForwarder:
                    case AuthZoneType.SecondaryCatalog:
                        (_apexZone as SecondaryZone).PrimaryZoneTransferProtocol = value;
                        break;

                    default:
                        throw new InvalidOperationException();
                }
            }
        }

        public string PrimaryZoneTransferTsigKeyName
        {
            get
            {
                if (_apexZone is null)
                    return _primaryZoneTransferTsigKeyName;

                switch (_type)
                {
                    case AuthZoneType.Secondary:
                    case AuthZoneType.SecondaryForwarder:
                    case AuthZoneType.SecondaryCatalog:
                        return (_apexZone as SecondaryZone).PrimaryZoneTransferTsigKeyName;

                    default:
                        throw new InvalidOperationException();
                }
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                switch (_type)
                {
                    case AuthZoneType.Secondary:
                    case AuthZoneType.SecondaryForwarder:
                    case AuthZoneType.SecondaryCatalog:
                        (_apexZone as SecondaryZone).PrimaryZoneTransferTsigKeyName = value;
                        break;

                    default:
                        throw new InvalidOperationException();
                }
            }
        }

        public DateTime Expiry
        {
            get
            {
                if (_apexZone is null)
                    return _expiry;

                switch (_type)
                {
                    case AuthZoneType.Secondary:
                    case AuthZoneType.SecondaryForwarder:
                    case AuthZoneType.SecondaryCatalog:
                        return (_apexZone as SecondaryZone).Expiry;

                    case AuthZoneType.Stub:
                        return (_apexZone as StubZone).Expiry;

                    default:
                        throw new InvalidOperationException();
                }
            }
        }

        public bool ValidateZone
        {
            get
            {
                if (_apexZone is null)
                    return _validateZone;

                switch (_type)
                {
                    case AuthZoneType.Secondary:
                        return (_apexZone as SecondaryZone).ValidateZone;

                    default:
                        throw new InvalidOperationException();
                }
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                switch (_type)
                {
                    case AuthZoneType.Secondary:
                        (_apexZone as SecondaryZone).ValidateZone = value;
                        break;

                    default:
                        throw new InvalidOperationException();
                }
            }
        }

        public bool ValidationFailed
        {
            get
            {
                if (_apexZone is null)
                    return _validationFailed;

                switch (_type)
                {
                    case AuthZoneType.Secondary:
                        return (_apexZone as SecondaryZone).ValidationFailed;

                    default:
                        throw new InvalidOperationException();
                }
            }
        }

        public uint DnsKeyTtl
        {
            get
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                switch (_type)
                {
                    case AuthZoneType.Primary:
                        return (_apexZone as PrimaryZone).GetDnsKeyTtl();

                    default:
                        throw new InvalidOperationException();
                }
            }
        }

        public bool Internal
        {
            get
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                switch (_type)
                {
                    case AuthZoneType.Primary:
                        return (_apexZone as PrimaryZone).Internal;

                    default:
                        return false;
                }
            }
        }

        public bool IsExpired
        {
            get
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                switch (_type)
                {
                    case AuthZoneType.Secondary:
                    case AuthZoneType.SecondaryForwarder:
                    case AuthZoneType.SecondaryCatalog:
                        return (_apexZone as SecondaryZone).IsExpired;

                    case AuthZoneType.Stub:
                        return (_apexZone as StubZone).IsExpired;

                    default:
                        return false;
                }
            }
        }

        public string[] NotifyFailed
        {
            get
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                switch (_type)
                {
                    case AuthZoneType.Primary:
                    case AuthZoneType.Secondary:
                    case AuthZoneType.Forwarder:
                    case AuthZoneType.Catalog:
                        return _apexZone.NotifyFailed;

                    default:
                        throw new InvalidOperationException();
                }
            }
        }

        public bool SyncFailed
        {
            get
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                switch (_type)
                {
                    case AuthZoneType.Secondary:
                    case AuthZoneType.SecondaryForwarder:
                    case AuthZoneType.SecondaryCatalog:
                    case AuthZoneType.Stub:
                        return _apexZone.SyncFailed;

                    default:
                        throw new InvalidOperationException();
                }
            }
        }

        #endregion
    }
}
