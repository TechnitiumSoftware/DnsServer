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

using System;
using System.Collections.Generic;
using System.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.ResourceRecords
{
    class CacheRecordInfo
    {
        #region variables

        public static readonly CacheRecordInfo Default = new CacheRecordInfo();

        IReadOnlyList<DnsResourceRecord> _glueRecords;
        IReadOnlyList<DnsResourceRecord> _rrsigRecords;
        IReadOnlyList<DnsResourceRecord> _nsecRecords;
        NetworkAddress _eDnsClientSubnet;

        DateTime _lastUsedOn; //not serialized

        #endregion

        #region constructor

        public CacheRecordInfo()
        { }

        public CacheRecordInfo(BinaryReader bR)
        {
            byte version = bR.ReadByte();
            switch (version)
            {
                case 1:
                    _glueRecords = ReadRecordsFrom(bR, true);
                    _rrsigRecords = ReadRecordsFrom(bR, false);
                    _nsecRecords = ReadRecordsFrom(bR, true);

                    if (bR.ReadBoolean())
                        _eDnsClientSubnet = NetworkAddress.ReadFrom(bR);

                    break;

                default:
                    throw new InvalidDataException("CacheRecordInfo format version not supported.");
            }
        }

        #endregion

        #region private

        private static IReadOnlyList<DnsResourceRecord> ReadRecordsFrom(BinaryReader bR, bool includeInnerRRSigRecords)
        {
            int count = bR.ReadByte();
            if (count == 0)
                return null;

            DnsResourceRecord[] records = new DnsResourceRecord[count];

            for (int i = 0; i < count; i++)
            {
                records[i] = DnsResourceRecord.ReadCacheRecordFrom(bR, delegate (DnsResourceRecord record)
                {
                    if (includeInnerRRSigRecords)
                    {
                        IReadOnlyList<DnsResourceRecord> rrsigRecords = ReadRecordsFrom(bR, false);
                        if (rrsigRecords is not null)
                            record.GetCacheRecordInfo()._rrsigRecords = rrsigRecords;
                    }
                });
            }

            return records;
        }

        private static void WriteRecordsTo(IReadOnlyList<DnsResourceRecord> records, BinaryWriter bW, bool includeInnerRRSigRecords)
        {
            if (records is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(records.Count));

                foreach (DnsResourceRecord record in records)
                {
                    record.WriteCacheRecordTo(bW, delegate ()
                    {
                        if (includeInnerRRSigRecords)
                        {
                            if (record.Tag is CacheRecordInfo cacheRecordInfo)
                                WriteRecordsTo(cacheRecordInfo._rrsigRecords, bW, false);
                            else
                                bW.Write((byte)0);
                        }
                    });
                }
            }
        }

        #endregion

        #region public

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write((byte)1); //version

            WriteRecordsTo(_glueRecords, bW, true);
            WriteRecordsTo(_rrsigRecords, bW, false);
            WriteRecordsTo(_nsecRecords, bW, true);

            if (_eDnsClientSubnet is null)
            {
                bW.Write(false);
            }
            else
            {
                bW.Write(true);
                _eDnsClientSubnet.WriteTo(bW);
            }
        }

        #endregion

        #region properties

        public IReadOnlyList<DnsResourceRecord> GlueRecords
        {
            get { return _glueRecords; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    _glueRecords = null;
                else
                    _glueRecords = value;
            }
        }

        public IReadOnlyList<DnsResourceRecord> RRSIGRecords
        {
            get { return _rrsigRecords; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    _rrsigRecords = null;
                else
                    _rrsigRecords = value;
            }
        }

        public IReadOnlyList<DnsResourceRecord> NSECRecords
        {
            get { return _nsecRecords; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    _nsecRecords = null;
                else
                    _nsecRecords = value;
            }
        }

        public NetworkAddress EDnsClientSubnet
        {
            get { return _eDnsClientSubnet; }
            set { _eDnsClientSubnet = value; }
        }

        public DateTime LastUsedOn
        {
            get { return _lastUsedOn; }
            set { _lastUsedOn = value; }
        }

        #endregion
    }
}
