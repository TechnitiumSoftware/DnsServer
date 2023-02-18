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

using DnsServerCore.Dns.Dnssec;
using DnsServerCore.Dns.ResourceRecords;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading.Tasks;
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
        Forwarder = 4
    }

    public sealed class AuthZoneInfo : IComparable<AuthZoneInfo>
    {
        #region variables

        readonly ApexZone _apexZone;

        readonly string _name;
        readonly AuthZoneType _type;
        readonly bool _disabled;
        readonly AuthZoneTransfer _zoneTransfer;
        readonly IReadOnlyCollection<IPAddress> _zoneTransferNameServers;
        readonly AuthZoneNotify _notify;
        readonly IReadOnlyCollection<IPAddress> _notifyNameServers;
        readonly AuthZoneUpdate _update;
        readonly IReadOnlyCollection<IPAddress> _updateIpAddresses;
        readonly DateTime _expiry;
        readonly IReadOnlyList<DnsResourceRecord> _zoneHistory; //for IXFR support
        readonly IReadOnlyDictionary<string, object> _zoneTransferTsigKeyNames;
        readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>> _updateSecurityPolicies;
        readonly IReadOnlyCollection<DnssecPrivateKey> _dnssecPrivateKeys;

        #endregion

        #region constructor

        public AuthZoneInfo(string name, AuthZoneType type, bool disabled)
        {
            _name = name;
            _type = type;
            _disabled = disabled;

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

        public AuthZoneInfo(BinaryReader bR)
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
                    _name = bR.ReadShortString();
                    _type = (AuthZoneType)bR.ReadByte();
                    _disabled = bR.ReadBoolean();

                    if (version >= 2)
                    {
                        {
                            _zoneTransfer = (AuthZoneTransfer)bR.ReadByte();

                            int count = bR.ReadByte();
                            if (count > 0)
                            {
                                IPAddress[] nameServers = new IPAddress[count];

                                for (int i = 0; i < count; i++)
                                    nameServers[i] = IPAddressExtensions.ReadFrom(bR);

                                _zoneTransferNameServers = nameServers;
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
                                IPAddress[] ipAddresses = new IPAddress[count];

                                for (int i = 0; i < count; i++)
                                    ipAddresses[i] = IPAddressExtensions.ReadFrom(bR);

                                _updateIpAddresses = ipAddresses;
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

                    switch (_type)
                    {
                        case AuthZoneType.Primary:
                            if (version >= 3)
                            {
                                int count = bR.ReadInt32();
                                DnsResourceRecord[] zoneHistory = new DnsResourceRecord[count];

                                for (int i = 0; i < count; i++)
                                {
                                    zoneHistory[i] = new DnsResourceRecord(bR.BaseStream);
                                    zoneHistory[i].Tag = new AuthRecordInfo(bR, zoneHistory[i].Type == DnsResourceRecordType.SOA);
                                }

                                _zoneHistory = zoneHistory;
                            }

                            if (version >= 4)
                            {
                                int count = bR.ReadByte();
                                Dictionary<string, object> tsigKeyNames = new Dictionary<string, object>(count);

                                for (int i = 0; i < count; i++)
                                    tsigKeyNames.Add(bR.ReadShortString(), null);

                                _zoneTransferTsigKeyNames = tsigKeyNames;
                            }

                            if (version >= 7)
                            {
                                int count = bR.ReadByte();
                                Dictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>> updateSecurityPolicies = new Dictionary<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>>(count);

                                for (int i = 0; i < count; i++)
                                {
                                    string tsigKeyName = bR.ReadShortString().ToLower();

                                    if (!updateSecurityPolicies.TryGetValue(tsigKeyName, out IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>> policyMap))
                                    {
                                        policyMap = new Dictionary<string, IReadOnlyList<DnsResourceRecordType>>();
                                        updateSecurityPolicies.Add(tsigKeyName, policyMap);
                                    }

                                    int policyCount = bR.ReadByte();

                                    for (int j = 0; j < policyCount; j++)
                                    {
                                        string domain = bR.ReadShortString().ToLower();

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
                                    updateSecurityPolicies.Add(bR.ReadShortString().ToLower(), defaultAllowPolicy);

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

                            break;

                        case AuthZoneType.Secondary:
                            _expiry = bR.ReadDateTime();

                            if (version >= 4)
                            {
                                int count = bR.ReadInt32();
                                DnsResourceRecord[] zoneHistory = new DnsResourceRecord[count];

                                for (int i = 0; i < count; i++)
                                {
                                    zoneHistory[i] = new DnsResourceRecord(bR.BaseStream);
                                    zoneHistory[i].Tag = new AuthRecordInfo(bR, zoneHistory[i].Type == DnsResourceRecordType.SOA);
                                }

                                _zoneHistory = zoneHistory;
                            }

                            if (version >= 4)
                            {
                                int count = bR.ReadByte();
                                Dictionary<string, object> tsigKeyNames = new Dictionary<string, object>(count);

                                for (int i = 0; i < count; i++)
                                    tsigKeyNames.Add(bR.ReadShortString(), null);

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

                            break;

                        case AuthZoneType.Stub:
                            _expiry = bR.ReadDateTime();
                            break;
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

            if (_apexZone is PrimaryZone primaryZone)
            {
                _type = AuthZoneType.Primary;

                if (loadHistory)
                    _zoneHistory = primaryZone.GetZoneHistory();

                _zoneTransferTsigKeyNames = primaryZone.ZoneTransferTsigKeyNames;
                _updateSecurityPolicies = primaryZone.UpdateSecurityPolicies;
                _dnssecPrivateKeys = primaryZone.DnssecPrivateKeys;
            }
            else if (_apexZone is SecondaryZone secondaryZone)
            {
                _type = AuthZoneType.Secondary;

                if (loadHistory)
                    _zoneHistory = secondaryZone.GetZoneHistory();

                _expiry = secondaryZone.Expiry;
                _zoneTransferTsigKeyNames = secondaryZone.ZoneTransferTsigKeyNames;
            }
            else if (_apexZone is StubZone stubZone)
            {
                _type = AuthZoneType.Stub;
                _expiry = stubZone.Expiry;
            }
            else if (_apexZone is ForwarderZone)
            {
                _type = AuthZoneType.Forwarder;
            }
            else
            {
                _type = AuthZoneType.Unknown;
            }

            _disabled = _apexZone.Disabled;
            _zoneTransfer = _apexZone.ZoneTransfer;
            _zoneTransferNameServers = _apexZone.ZoneTransferNameServers;
            _notify = _apexZone.Notify;
            _notifyNameServers = _apexZone.NotifyNameServers;
            _update = _apexZone.Update;
            _updateIpAddresses = _apexZone.UpdateIpAddresses;
        }

        #endregion

        #region public

        public IReadOnlyList<DnsResourceRecord> GetApexRecords(DnsResourceRecordType type)
        {
            if (_apexZone is null)
                throw new InvalidOperationException();

            return _apexZone.GetRecords(type);
        }

        public void TriggerNotify()
        {
            if (_apexZone is null)
                throw new InvalidOperationException();

            switch (_type)
            {
                case AuthZoneType.Primary:
                    (_apexZone as PrimaryZone).TriggerNotify();
                    break;

                case AuthZoneType.Secondary:
                    (_apexZone as SecondaryZone).TriggerNotify();
                    break;

                default:
                    throw new InvalidOperationException();
            }
        }

        public void TriggerRefresh()
        {
            if (_apexZone is null)
                throw new InvalidOperationException();

            switch (_type)
            {
                case AuthZoneType.Secondary:
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
                    (_apexZone as SecondaryZone).TriggerResync();
                    break;

                case AuthZoneType.Stub:
                    (_apexZone as StubZone).TriggerResync();
                    break;

                default:
                    throw new InvalidOperationException();
            }
        }

        public Task<IReadOnlyList<NameServerAddress>> GetPrimaryNameServerAddressesAsync(DnsServer dnsServer)
        {
            if (_apexZone is null)
                throw new InvalidOperationException();

            return _apexZone.GetPrimaryNameServerAddressesAsync(dnsServer);
        }

        public Task<IReadOnlyList<NameServerAddress>> GetSecondaryNameServerAddressesAsync(DnsServer dnsServer)
        {
            if (_apexZone is null)
                throw new InvalidOperationException();

            return _apexZone.GetSecondaryNameServerAddressesAsync(dnsServer);
        }

        public void WriteTo(BinaryWriter bW)
        {
            if (_apexZone is null)
                throw new InvalidOperationException();

            bW.Write((byte)7); //version

            bW.WriteShortString(_name);
            bW.Write((byte)_type);
            bW.Write(_disabled);
            bW.Write((byte)_zoneTransfer);

            if (_zoneTransferNameServers is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_zoneTransferNameServers.Count));
                foreach (IPAddress nameServer in _zoneTransferNameServers)
                    nameServer.WriteTo(bW);
            }

            bW.Write((byte)_notify);

            if (_notifyNameServers is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_notifyNameServers.Count));
                foreach (IPAddress nameServer in _notifyNameServers)
                    nameServer.WriteTo(bW);
            }

            bW.Write((byte)_update);

            if (_updateIpAddresses is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_updateIpAddresses.Count));
                foreach (IPAddress ipAddress in _updateIpAddresses)
                    ipAddress.WriteTo(bW);
            }

            switch (_type)
            {
                case AuthZoneType.Primary:
                    if (_zoneHistory is null)
                    {
                        bW.Write(0);
                    }
                    else
                    {
                        bW.Write(_zoneHistory.Count);

                        foreach (DnsResourceRecord record in _zoneHistory)
                        {
                            record.WriteTo(bW.BaseStream);

                            if (record.Tag is not AuthRecordInfo rrInfo)
                                rrInfo = AuthRecordInfo.Default; //default info

                            rrInfo.WriteTo(bW);
                        }
                    }

                    if (_zoneTransferTsigKeyNames is null)
                    {
                        bW.Write((byte)0);
                    }
                    else
                    {
                        bW.Write(Convert.ToByte(_zoneTransferTsigKeyNames.Count));

                        foreach (KeyValuePair<string, object> tsigKeyName in _zoneTransferTsigKeyNames)
                            bW.WriteShortString(tsigKeyName.Key);
                    }

                    if (_updateSecurityPolicies is null)
                    {
                        bW.Write((byte)0);
                    }
                    else
                    {
                        bW.Write(Convert.ToByte(_updateSecurityPolicies.Count));

                        foreach (KeyValuePair<string, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>>> updateSecurityPolicy in _updateSecurityPolicies)
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

                    if (_dnssecPrivateKeys is null)
                    {
                        bW.Write((byte)0);
                    }
                    else
                    {
                        bW.Write(Convert.ToByte(_dnssecPrivateKeys.Count));

                        foreach (DnssecPrivateKey dnssecPrivateKey in _dnssecPrivateKeys)
                            dnssecPrivateKey.WriteTo(bW);
                    }
                    break;

                case AuthZoneType.Secondary:
                    bW.Write(_expiry);

                    if (_zoneHistory is null)
                    {
                        bW.Write(0);
                    }
                    else
                    {
                        bW.Write(_zoneHistory.Count);

                        foreach (DnsResourceRecord record in _zoneHistory)
                        {
                            record.WriteTo(bW.BaseStream);

                            if (record.Tag is not AuthRecordInfo rrInfo)
                                rrInfo = AuthRecordInfo.Default; //default info

                            rrInfo.WriteTo(bW);
                        }
                    }

                    if (_zoneTransferTsigKeyNames is null)
                    {
                        bW.Write((byte)0);
                    }
                    else
                    {
                        bW.Write(Convert.ToByte(_zoneTransferTsigKeyNames.Count));

                        foreach (KeyValuePair<string, object> tsigKeyName in _zoneTransferTsigKeyNames)
                            bW.WriteShortString(tsigKeyName.Key);
                    }

                    break;

                case AuthZoneType.Stub:
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
            return _name.GetHashCode();
        }

        public override string ToString()
        {
            return _name;
        }

        #endregion

        #region properties

        internal ApexZone ApexZone
        { get { return _apexZone; } }

        public string Name
        { get { return _name; } }

        public AuthZoneType Type
        { get { return _type; } }

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

        public IReadOnlyCollection<IPAddress> ZoneTransferNameServers
        {
            get
            {
                if (_apexZone is null)
                    return _zoneTransferNameServers;

                return _apexZone.ZoneTransferNameServers;
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                _apexZone.ZoneTransferNameServers = value;
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

        public IReadOnlyCollection<IPAddress> UpdateIpAddresses
        {
            get
            {
                if (_apexZone is null)
                    return _updateIpAddresses;

                return _apexZone.UpdateIpAddresses;
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                _apexZone.UpdateIpAddresses = value;
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
                        return (_apexZone as SecondaryZone).Expiry;

                    case AuthZoneType.Stub:
                        return (_apexZone as StubZone).Expiry;

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

        public IReadOnlyDictionary<string, object> ZoneTransferTsigKeyNames
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
                        _apexZone.ZoneTransferTsigKeyNames = value;
                        break;

                    default:
                        throw new InvalidOperationException();
                }
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

                    default:
                        throw new InvalidOperationException();
                }
            }
        }

        public AuthZoneDnssecStatus DnssecStatus
        {
            get
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                return _apexZone.DnssecStatus;
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
                        return (_apexZone as SecondaryZone).IsExpired;

                    case AuthZoneType.Stub:
                        return (_apexZone as StubZone).IsExpired;

                    default:
                        return false;
                }
            }
        }

        public bool NotifyFailed
        {
            get
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                switch (_type)
                {
                    case AuthZoneType.Primary:
                        return (_apexZone as PrimaryZone).NotifyFailed;

                    case AuthZoneType.Secondary:
                        return (_apexZone as SecondaryZone).NotifyFailed;

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
                        return (_apexZone as SecondaryZone).SyncFailed;

                    case AuthZoneType.Stub:
                        return (_apexZone as StubZone).SyncFailed;

                    default:
                        throw new InvalidOperationException();
                }
            }
        }

        #endregion
    }
}
