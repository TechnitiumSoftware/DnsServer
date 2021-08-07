/*
Technitium DNS Server
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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
using System.IO;
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;

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

        readonly AuthZone _zone;

        readonly string _name;
        readonly AuthZoneType _type;
        readonly bool _disabled;
        readonly AuthZoneTransfer _zoneTransfer;
        readonly IReadOnlyCollection<IPAddress> _zoneTransferNameServers;
        readonly AuthZoneNotify _notify;
        readonly IReadOnlyCollection<IPAddress> _notifyNameServers;
        readonly DateTime _expiry;
        readonly IReadOnlyList<DnsResourceRecord> _zoneHistory; //for IXFR support
        readonly IReadOnlyDictionary<string, object> _tsigKeyNames;

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
                    break;

                default:
                    _zoneTransfer = AuthZoneTransfer.Deny;
                    _notify = AuthZoneNotify.None;
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
                                    nameServers[i] = IPAddressExtension.Parse(bR);

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
                                    nameServers[i] = IPAddressExtension.Parse(bR);

                                _notifyNameServers = nameServers;
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
                                break;

                            default:
                                _zoneTransfer = AuthZoneTransfer.Deny;
                                _notify = AuthZoneNotify.None;
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
                                    zoneHistory[i].Tag = new DnsResourceRecordInfo(bR, zoneHistory[i].Type == DnsResourceRecordType.SOA);
                                }

                                _zoneHistory = zoneHistory;
                            }

                            if (version >= 4)
                            {
                                int count = bR.ReadByte();
                                Dictionary<string, object> tsigKeyNames = new Dictionary<string, object>(count);

                                for (int i = 0; i < count; i++)
                                    tsigKeyNames.Add(bR.ReadShortString(), null);

                                _tsigKeyNames = tsigKeyNames;
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
                                    zoneHistory[i].Tag = new DnsResourceRecordInfo(bR, zoneHistory[i].Type == DnsResourceRecordType.SOA);
                                }

                                _zoneHistory = zoneHistory;
                            }

                            if (version >= 4)
                            {
                                int count = bR.ReadByte();
                                Dictionary<string, object> tsigKeyNames = new Dictionary<string, object>(count);

                                for (int i = 0; i < count; i++)
                                    tsigKeyNames.Add(bR.ReadShortString(), null);

                                _tsigKeyNames = tsigKeyNames;
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

        internal AuthZoneInfo(AuthZone zone, bool loadHistory = false)
        {
            _zone = zone;
            _name = _zone.Name;

            if (_zone is PrimaryZone primaryZone)
            {
                _type = AuthZoneType.Primary;

                if (loadHistory)
                    _zoneHistory = primaryZone.GetHistory();

                _tsigKeyNames = primaryZone.TsigKeyNames;
            }
            else if (_zone is SecondaryZone secondaryZone)
            {
                _type = AuthZoneType.Secondary;

                if (loadHistory)
                    _zoneHistory = secondaryZone.GetHistory();

                _expiry = secondaryZone.Expiry;
                _tsigKeyNames = secondaryZone.TsigKeyNames;
            }
            else if (_zone is StubZone stubZone)
            {
                _type = AuthZoneType.Stub;
                _expiry = stubZone.Expiry;
            }
            else if (_zone is ForwarderZone)
            {
                _type = AuthZoneType.Forwarder;
            }
            else
            {
                _type = AuthZoneType.Unknown;
            }

            _disabled = _zone.Disabled;
            _zoneTransfer = zone.ZoneTransfer;
            _zoneTransferNameServers = zone.ZoneTransferNameServers;
            _notify = zone.Notify;
            _notifyNameServers = zone.NotifyNameServers;
        }

        #endregion

        #region public

        public IReadOnlyList<DnsResourceRecord> GetRecords(DnsResourceRecordType type)
        {
            if (_zone == null)
                throw new InvalidOperationException();

            return _zone.GetRecords(type);
        }

        public void TriggerNotify()
        {
            if (_zone == null)
                throw new InvalidOperationException();

            switch (_type)
            {
                case AuthZoneType.Primary:
                    (_zone as PrimaryZone).TriggerNotify();
                    break;

                case AuthZoneType.Secondary:
                    (_zone as SecondaryZone).TriggerNotify();
                    break;

                default:
                    throw new InvalidOperationException();
            }
        }

        public void TriggerRefresh()
        {
            if (_zone == null)
                throw new InvalidOperationException();

            switch (_type)
            {
                case AuthZoneType.Secondary:
                    (_zone as SecondaryZone).TriggerRefresh();
                    break;

                case AuthZoneType.Stub:
                    (_zone as StubZone).TriggerRefresh();
                    break;

                default:
                    throw new InvalidOperationException();
            }
        }

        public void TriggerResync()
        {
            if (_zone == null)
                throw new InvalidOperationException();

            switch (_type)
            {
                case AuthZoneType.Secondary:
                    (_zone as SecondaryZone).TriggerResync();
                    break;

                case AuthZoneType.Stub:
                    (_zone as StubZone).TriggerResync();
                    break;

                default:
                    throw new InvalidOperationException();
            }
        }

        public Task<IReadOnlyList<NameServerAddress>> GetPrimaryNameServerAddressesAsync(DnsServer dnsServer)
        {
            if (_zone == null)
                throw new InvalidOperationException();

            return _zone.GetPrimaryNameServerAddressesAsync(dnsServer);
        }

        public Task<IReadOnlyList<NameServerAddress>> GetSecondaryNameServerAddressesAsync(DnsServer dnsServer)
        {
            if (_zone == null)
                throw new InvalidOperationException();

            return _zone.GetSecondaryNameServerAddressesAsync(dnsServer);
        }

        public void WriteTo(BinaryWriter bW)
        {
            if (_zone == null)
                throw new InvalidOperationException();

            bW.Write((byte)4); //version

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

                            if (record.Tag is not DnsResourceRecordInfo rrInfo)
                                rrInfo = new DnsResourceRecordInfo(); //default info

                            rrInfo.WriteTo(bW);
                        }
                    }

                    if (_tsigKeyNames is null)
                    {
                        bW.Write((byte)0);
                    }
                    else
                    {
                        bW.Write(Convert.ToByte(_tsigKeyNames.Count));

                        foreach (KeyValuePair<string, object> tsigKeyName in _tsigKeyNames)
                            bW.WriteShortString(tsigKeyName.Key);
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

                            if (record.Tag is not DnsResourceRecordInfo rrInfo)
                                rrInfo = new DnsResourceRecordInfo(); //default info

                            rrInfo.WriteTo(bW);
                        }
                    }

                    if (_tsigKeyNames is null)
                    {
                        bW.Write((byte)0);
                    }
                    else
                    {
                        bW.Write(Convert.ToByte(_tsigKeyNames.Count));

                        foreach (KeyValuePair<string, object> tsigKeyName in _tsigKeyNames)
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

        public override string ToString()
        {
            return _name;
        }

        #endregion

        #region properties

        public string Name
        { get { return _name; } }

        public AuthZoneType Type
        { get { return _type; } }

        public bool Disabled
        {
            get { return _disabled; }
            set
            {
                if (_zone is null)
                    throw new InvalidOperationException();

                _zone.Disabled = value;
            }
        }

        public AuthZoneTransfer ZoneTransfer
        {
            get { return _zoneTransfer; }
            set
            {
                if (_zone is null)
                    throw new InvalidOperationException();

                _zone.ZoneTransfer = value;
            }
        }

        public IReadOnlyCollection<IPAddress> ZoneTransferNameServers
        {
            get { return _zoneTransferNameServers; }
            set
            {
                if (_zone is null)
                    throw new InvalidOperationException();

                _zone.ZoneTransferNameServers = value;
            }
        }

        public AuthZoneNotify Notify
        {
            get { return _notify; }
            set
            {
                if (_zone is null)
                    throw new InvalidOperationException();

                _zone.Notify = value;
            }
        }

        public IReadOnlyCollection<IPAddress> NotifyNameServers
        {
            get { return _notifyNameServers; }
            set
            {
                if (_zone is null)
                    throw new InvalidOperationException();

                _zone.NotifyNameServers = value;
            }
        }

        public DateTime Expiry
        { get { return _expiry; } }

        public bool IsExpired
        {
            get
            {
                if (_zone == null)
                    throw new InvalidOperationException();

                if (_zone is SecondaryZone secondaryZone)
                    return secondaryZone.IsExpired;

                if (_zone is StubZone stubZone)
                    return stubZone.IsExpired;

                return false;
            }
        }

        public bool Internal
        {
            get
            {
                if (_zone == null)
                    throw new InvalidOperationException();

                if (_zone is PrimaryZone primaryZone)
                    return primaryZone.Internal;

                return false;
            }
        }

        public IReadOnlyList<DnsResourceRecord> ZoneHistory
        { get { return _zoneHistory; } }

        public IReadOnlyDictionary<string, object> TsigKeyNames
        {
            get { return _tsigKeyNames; }
            set
            {
                if (_zone is null)
                    throw new InvalidOperationException();

                switch (_type)
                {
                    case AuthZoneType.Primary:
                        (_zone as PrimaryZone).TsigKeyNames = value;
                        break;

                    case AuthZoneType.Secondary:
                        (_zone as SecondaryZone).TsigKeyNames = value;
                        break;

                    default:
                        throw new InvalidOperationException();
                }
            }
        }

        #endregion
    }
}
