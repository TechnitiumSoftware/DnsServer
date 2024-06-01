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
using System.IO;
using System.Net;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.ResourceRecords
{
    abstract class AuthRecordInfo
    {
        #region constructor

        protected AuthRecordInfo()
        { }

        protected AuthRecordInfo(BinaryReader bR)
        {
            byte version = bR.ReadByte();
            if (version >= 9)
                ReadRecordInfoFrom(bR);
            else
                ReadOldFormatFrom(bR, version, this is SOARecordInfo);
        }

        #endregion

        #region static

        public static GenericRecordInfo ReadGenericRecordInfoFrom(BinaryReader bR, DnsResourceRecordType type)
        {
            switch (type)
            {
                case DnsResourceRecordType.NS:
                    return new NSRecordInfo(bR);

                case DnsResourceRecordType.SOA:
                    return new SOARecordInfo(bR);

                case DnsResourceRecordType.SVCB:
                case DnsResourceRecordType.HTTPS:
                    return new SVCBRecordInfo(bR);

                default:
                    return new GenericRecordInfo(bR);
            }
        }

        #endregion

        #region private

        private void ReadOldFormatFrom(BinaryReader bR, byte version, bool isSoa)
        {
            switch (version)
            {
                case 1:
                    {
                        bool disabled = bR.ReadBoolean();

                        if (this is GenericRecordInfo info)
                            info.Disabled = disabled;
                    }
                    break;

                case 2:
                case 3:
                case 4:
                case 5:
                case 6:
                case 7:
                case 8:
                    {
                        {
                            bool disabled = bR.ReadBoolean();

                            if (this is GenericRecordInfo info)
                                info.Disabled = disabled;
                        }

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
                                            address = (glueRecord.RDATA as DnsARecordData).Address;
                                            break;

                                        case DnsResourceRecordType.AAAA:
                                            address = (glueRecord.RDATA as DnsAAAARecordData).Address;
                                            break;

                                        default:
                                            continue;
                                    }

                                    primaryNameServers[i] = new NameServerAddress(address);
                                }

                                (this as SOARecordInfo).PrimaryNameServers = primaryNameServers;
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

                                if (this is NSRecordInfo info)
                                    info.GlueRecords = glueRecords;
                            }
                        }

                        if (version >= 3)
                        {
                            string comments = bR.ReadShortString();

                            if (this is GenericRecordInfo info)
                                info.Comments = comments;
                        }

                        if (version >= 4)
                        {
                            DateTime deletedOn = bR.ReadDateTime();

                            if (this is HistoryRecordInfo info)
                                info.DeletedOn = deletedOn;
                        }

                        if (version >= 5)
                        {
                            int count = bR.ReadByte();
                            if (count > 0)
                            {
                                NameServerAddress[] primaryNameServers = new NameServerAddress[count];

                                for (int i = 0; i < primaryNameServers.Length; i++)
                                    primaryNameServers[i] = new NameServerAddress(bR);

                                if (this is SOARecordInfo info)
                                    info.PrimaryNameServers = primaryNameServers;
                            }
                        }

                        if (version >= 7)
                        {
                            DnsTransportProtocol zoneTransferProtocol = (DnsTransportProtocol)bR.ReadByte();
                            string tsigKeyName = bR.ReadShortString();

                            if (this is SOARecordInfo info)
                            {
                                if (zoneTransferProtocol != DnsTransportProtocol.Udp)
                                    info.ZoneTransferProtocol = zoneTransferProtocol;

                                if (tsigKeyName.Length > 0)
                                    info.TsigKeyName = tsigKeyName;
                            }
                        }
                        else if (version >= 6)
                        {
                            DnsTransportProtocol zoneTransferProtocol = (DnsTransportProtocol)bR.ReadByte();

                            string tsigKeyName = bR.ReadShortString();
                            _ = bR.ReadShortString(); //_tsigSharedSecret (obsolete)
                            _ = bR.ReadShortString(); //_tsigAlgorithm (obsolete)

                            if (this is SOARecordInfo info)
                            {
                                if (zoneTransferProtocol != DnsTransportProtocol.Udp)
                                    info.ZoneTransferProtocol = zoneTransferProtocol;

                                if (tsigKeyName.Length > 0)
                                    info.TsigKeyName = tsigKeyName;
                            }
                        }

                        if (version >= 8)
                        {
                            bool useSoaSerialDateScheme = bR.ReadBoolean();

                            if (this is SOARecordInfo info)
                                info.UseSoaSerialDateScheme = useSoaSerialDateScheme;
                        }
                    }
                    break;

                default:
                    throw new InvalidDataException("AuthRecordInfo format version not supported.");
            }
        }

        #endregion

        #region protected

        protected abstract void ReadRecordInfoFrom(BinaryReader bR);

        protected abstract void WriteRecordInfoTo(BinaryWriter bW);

        #endregion

        #region public

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write((byte)9); //version

            WriteRecordInfoTo(bW);
        }

        #endregion
    }
}
