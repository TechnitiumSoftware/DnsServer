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
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.ResourceRecords
{
    class NSRecordInfo : GenericRecordInfo
    {
        #region variables

        IReadOnlyList<DnsResourceRecord> _glueRecords;

        #endregion

        #region constructor

        public NSRecordInfo()
        { }

        public NSRecordInfo(BinaryReader bR)
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
                        DnsResourceRecord[] glueRecords = new DnsResourceRecord[count];

                        for (int i = 0; i < glueRecords.Length; i++)
                            glueRecords[i] = new DnsResourceRecord(bR.BaseStream);

                        _glueRecords = glueRecords;
                    }
                    break;

                default:
                    throw new InvalidDataException("NSRecordInfo format version not supported.");
            }
        }

        protected override void WriteExtendedRecordInfoTo(BinaryWriter bW)
        {
            bW.Write((byte)1); //version

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

        #endregion
    }
}
