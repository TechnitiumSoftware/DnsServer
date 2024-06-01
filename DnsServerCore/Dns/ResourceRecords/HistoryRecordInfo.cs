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
using TechnitiumLibrary.IO;

namespace DnsServerCore.Dns.ResourceRecords
{
    class HistoryRecordInfo : AuthRecordInfo
    {
        #region variables

        DateTime _deletedOn;

        #endregion

        #region constructor

        public HistoryRecordInfo()
        { }

        public HistoryRecordInfo(BinaryReader bR)
            : base(bR)
        { }

        #endregion

        #region static

        public static HistoryRecordInfo ReadFrom(BinaryReader bR)
        {
            return new HistoryRecordInfo(bR);
        }

        #endregion

        #region protected

        protected override void ReadRecordInfoFrom(BinaryReader bR)
        {
            byte version = bR.ReadByte();
            switch (version)
            {
                case 1:
                    _deletedOn = bR.ReadDateTime();
                    break;

                default:
                    throw new InvalidDataException("HistoryRecordInfo format version not supported.");
            }
        }

        protected override void WriteRecordInfoTo(BinaryWriter bW)
        {
            bW.Write((byte)1); //version

            bW.Write(_deletedOn);
        }

        #endregion

        #region properties

        public DateTime DeletedOn
        {
            get { return _deletedOn; }
            set { _deletedOn = value; }
        }

        #endregion
    }
}
