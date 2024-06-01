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

using System;
using System.Collections.Generic;
using System.IO;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Dns.ResourceRecords
{
    class SOARecordInfo : GenericRecordInfo
    {
        #region variables

        IReadOnlyList<NameServerAddress> _primaryNameServers;
        DnsTransportProtocol _zoneTransferProtocol;
        string _tsigKeyName = string.Empty;
        bool _useSoaSerialDateScheme;

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
            byte version = bR.ReadByte();
            switch (version)
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

                default:
                    throw new InvalidDataException("SOARecordInfo format version not supported.");
            }
        }

        protected override void WriteExtendedRecordInfoTo(BinaryWriter bW)
        {
            bW.Write((byte)1); //version

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
            bW.Write(_useSoaSerialDateScheme);
        }

        #endregion

        #region properties

        public IReadOnlyList<NameServerAddress> PrimaryNameServers
        {
            get { return _primaryNameServers; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    _primaryNameServers = null;
                else
                    _primaryNameServers = value;
            }
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
                    case DnsTransportProtocol.Quic:
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

        public bool UseSoaSerialDateScheme
        {
            get { return _useSoaSerialDateScheme; }
            set { _useSoaSerialDateScheme = value; }
        }

        #endregion
    }
}
