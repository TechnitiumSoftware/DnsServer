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

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.ResourceRecords
{
    class DnsResourceRecordInfo
    {
        #region variables

        bool _disabled;
        IReadOnlyList<DnsResourceRecord> _glueRecords;
        string _comments;
        DateTime _deletedOn;
        IReadOnlyList<NameServerAddress> _primaryNameServers;
        DnsTransportProtocol _zoneTransferProtocol;
        string _tsigKeyName = string.Empty;

        #endregion

        #region constructor

        public DnsResourceRecordInfo()
        { }

        public DnsResourceRecordInfo(BinaryReader bR, bool isSoa)
        {
            byte version = bR.ReadByte();
            switch (version)
            {
                case 1:
                    _disabled = bR.ReadBoolean();
                    break;

                case 2:
                case 3:
                case 4:
                case 5:
                case 6:
                case 7:
                    _disabled = bR.ReadBoolean();

                    if ((version < 5) && isSoa)
                    {
                        //read old glue records as NameServerAddress in case of SOA record
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            NameServerAddress[] primaryNameServers = new NameServerAddress[count];

                            for (int i = 0; i < primaryNameServers.Length; i++)
                            {
                                DnsResourceRecord glueRecord = new DnsResourceRecord(bR.BaseStream);

                                IPAddress address;

                                switch (glueRecord.Type)
                                {
                                    case DnsResourceRecordType.A:
                                        address = (glueRecord.RDATA as DnsARecord).Address;
                                        break;

                                    case DnsResourceRecordType.AAAA:
                                        address = (glueRecord.RDATA as DnsAAAARecord).Address;
                                        break;

                                    default:
                                        continue;
                                }

                                primaryNameServers[i] = new NameServerAddress(address);
                            }

                            _primaryNameServers = primaryNameServers;
                        }
                    }
                    else
                    {
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            DnsResourceRecord[] glueRecords = new DnsResourceRecord[count];

                            for (int i = 0; i < glueRecords.Length; i++)
                                glueRecords[i] = new DnsResourceRecord(bR.BaseStream);

                            _glueRecords = glueRecords;
                        }
                    }

                    if (version >= 3)
                        _comments = bR.ReadShortString();

                    if (version >= 4)
                        _deletedOn = bR.ReadDateTime();

                    if (version >= 5)
                    {
                        int count = bR.ReadByte();
                        if (count > 0)
                        {
                            NameServerAddress[] primaryNameServers = new NameServerAddress[count];

                            for (int i = 0; i < primaryNameServers.Length; i++)
                                primaryNameServers[i] = new NameServerAddress(bR);

                            _primaryNameServers = primaryNameServers;
                        }
                    }

                    if (version >= 7)
                    {
                        _zoneTransferProtocol = (DnsTransportProtocol)bR.ReadByte();

                        _tsigKeyName = bR.ReadShortString();
                    }
                    else if (version >= 6)
                    {
                        _zoneTransferProtocol = (DnsTransportProtocol)bR.ReadByte();

                        _tsigKeyName = bR.ReadShortString();
                        _ = bR.ReadShortString(); //_tsigSharedSecret (obsolete)
                        _ = bR.ReadShortString(); //_tsigAlgorithm (obsolete)
                    }

                    break;

                default:
                    throw new InvalidDataException("DnsResourceRecordInfo format version not supported.");
            }
        }

        #endregion

        #region public

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write((byte)7); //version
            bW.Write(_disabled);

            if (_glueRecords is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_glueRecords.Count));

                foreach (DnsResourceRecord glueRecord in _glueRecords)
                    glueRecord.WriteTo(bW.BaseStream);
            }

            if (string.IsNullOrEmpty(_comments))
                bW.Write((byte)0);
            else
                bW.WriteShortString(_comments);

            bW.Write(_deletedOn);

            if (_primaryNameServers is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_primaryNameServers.Count));

                foreach (NameServerAddress nameServer in _primaryNameServers)
                    nameServer.WriteTo(bW);
            }

            bW.Write((byte)_zoneTransferProtocol);

            bW.WriteShortString(_tsigKeyName);
        }

        #endregion

        #region properties

        public bool Disabled
        {
            get { return _disabled; }
            set { _disabled = value; }
        }

        public IReadOnlyList<DnsResourceRecord> GlueRecords
        {
            get { return _glueRecords; }
            set { _glueRecords = value; }
        }

        public string Comments
        {
            get { return _comments; }
            set { _comments = value; }
        }

        public DateTime DeletedOn
        {
            get { return _deletedOn; }
            set { _deletedOn = value; }
        }

        public IReadOnlyList<NameServerAddress> PrimaryNameServers
        {
            get { return _primaryNameServers; }
            set { _primaryNameServers = value; }
        }

        public DnsTransportProtocol ZoneTransferProtocol
        {
            get { return _zoneTransferProtocol; }
            set
            {
                switch (value)
                {
                    case DnsTransportProtocol.Tcp:
                    case DnsTransportProtocol.Tls:
                        _zoneTransferProtocol = value;
                        break;

                    default:
                        throw new NotSupportedException("Zone transfer protocol is not supported: XFR-over-" + value.ToString().ToUpper());
                }
            }
        }

        public string TsigKeyName
        {
            get { return _tsigKeyName; }
            set
            {
                if (value is null)
                    _tsigKeyName = string.Empty;
                else
                    _tsigKeyName = value;
            }
        }

        #endregion
    }
}
