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

using System.Collections.Generic;
using System.IO;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Dns.ResourceRecords
{
    class SOARecordInfo : GenericRecordInfo
    {
        #region variables

        byte _version;
        bool _useSoaSerialDateScheme;

        IReadOnlyList<NameServerAddress> _primaryNameServers; //depricated
        DnsTransportProtocol _zoneTransferProtocol; //depricated
        string _tsigKeyName = string.Empty; //depricated

        #endregion

        #region constructor

        public SOARecordInfo()
        { }

        public SOARecordInfo(BinaryReader bR)
            : base(bR)
        { }

        #endregion

        #region protected

        protected override void ReadExtendedRecordInfoFrom(BinaryReader bR)
        {
            _version = bR.ReadByte();
            switch (_version)
            {
                case 0: //no extended info
                    break;

                case 1:
                    int count = bR.ReadByte();
                    if (count > 0)
                    {
                        NameServerAddress[] primaryNameServers = new NameServerAddress[count];

                        for (int i = 0; i < primaryNameServers.Length; i++)
                            primaryNameServers[i] = new NameServerAddress(bR);

                        _primaryNameServers = primaryNameServers;
                    }

                    _zoneTransferProtocol = (DnsTransportProtocol)bR.ReadByte();
                    _tsigKeyName = bR.ReadShortString();
                    _useSoaSerialDateScheme = bR.ReadBoolean();
                    break;

                case 2:
                    _useSoaSerialDateScheme = bR.ReadBoolean();
                    break;

                default:
                    throw new InvalidDataException("SOARecordInfo format version not supported.");
            }
        }

        protected override void WriteExtendedRecordInfoTo(BinaryWriter bW)
        {
            bW.Write((byte)2); //version

            bW.Write(_useSoaSerialDateScheme);
        }

        #endregion

        #region properties

        public override bool Disabled
        {
            get { return base.Disabled; }
            set
            {
                //cannot disable SOA            
            }
        }

        public override uint ExpiryTtl
        {
            get { return base.ExpiryTtl; }
            set
            {
                //cannot expire SOA
            }
        }

        public byte Version
        { get { return _version; } }

        public bool UseSoaSerialDateScheme
        {
            get { return _useSoaSerialDateScheme; }
            set { _useSoaSerialDateScheme = value; }
        }

        public IReadOnlyList<NameServerAddress> PrimaryNameServers
        {
            get { return _primaryNameServers; }
            set { _primaryNameServers = value; }
        }

        public DnsTransportProtocol ZoneTransferProtocol
        {
            get { return _zoneTransferProtocol; }
            set { _zoneTransferProtocol = value; }
        }

        public string TsigKeyName
        {
            get { return _tsigKeyName; }
            set { _tsigKeyName = value; }
        }

        #endregion
    }
}
