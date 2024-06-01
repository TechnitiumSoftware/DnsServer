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
    class GenericRecordInfo : AuthRecordInfo
    {
        #region variables

        bool _disabled;
        string _comments;

        DateTime _lastUsedOn; //not serialized

        #endregion

        #region constructor

        public GenericRecordInfo()
        { }

        public GenericRecordInfo(BinaryReader bR)
            : base(bR)
        { }

        #endregion

        #region protected

        protected sealed override void ReadRecordInfoFrom(BinaryReader bR)
        {
            byte version = bR.ReadByte();
            switch (version)
            {
                case 1:
                    _disabled = bR.ReadBoolean();
                    _comments = bR.ReadShortString();

                    ReadExtendedRecordInfoFrom(bR);
                    break;

                default:
                    throw new InvalidDataException("GenericRecordInfo format version not supported.");
            }
        }

        protected sealed override void WriteRecordInfoTo(BinaryWriter bW)
        {
            bW.Write((byte)1); //version

            bW.Write(_disabled);

            if (string.IsNullOrEmpty(_comments))
                bW.Write((byte)0);
            else
                bW.WriteShortString(_comments);

            WriteExtendedRecordInfoTo(bW);
        }

        protected virtual void ReadExtendedRecordInfoFrom(BinaryReader bR)
        {
            _ = bR.ReadByte(); //read byte to move ahead
        }

        protected virtual void WriteExtendedRecordInfoTo(BinaryWriter bW)
        {
            bW.Write((byte)0); //no extended info
        }

        #endregion

        #region properties

        public bool Disabled
        {
            get { return _disabled; }
            set { _disabled = value; }
        }

        public string Comments
        {
            get { return _comments; }
            set
            {
                if ((value is not null) && (value.Length > 255))
                    throw new ArgumentOutOfRangeException(nameof(Comments), "Resource record comment text cannot exceed 255 characters.");

                _comments = value;
            }
        }

        public DateTime LastUsedOn
        {
            get { return _lastUsedOn; }
            set { _lastUsedOn = value; }
        }

        #endregion
    }
}
