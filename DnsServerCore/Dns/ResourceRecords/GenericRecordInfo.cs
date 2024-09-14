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
        DateTime _lastModified;
        uint _expiryTtl;

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

                case 2:
                    _disabled = bR.ReadBoolean();
                    _comments = bR.ReadShortString();

                    _lastModified = bR.ReadDateTime();
                    _expiryTtl = bR.ReadUInt32();

                    ReadExtendedRecordInfoFrom(bR);
                    break;

                default:
                    throw new InvalidDataException("GenericRecordInfo format version not supported.");
            }
        }

        protected sealed override void WriteRecordInfoTo(BinaryWriter bW)
        {
            bW.Write((byte)2); //version

            bW.Write(_disabled);

            if (string.IsNullOrEmpty(_comments))
                bW.Write((byte)0);
            else
                bW.WriteShortString(_comments);

            bW.Write(_lastModified);
            bW.Write(_expiryTtl);

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

        #region public

        public uint GetPendingExpiryTtl()
        {
            uint elapsedSeconds = Convert.ToUInt32((DateTime.UtcNow - _lastModified).TotalSeconds);
            if (elapsedSeconds < _expiryTtl)
                return _expiryTtl - elapsedSeconds;

            return 0u;
        }

        #endregion

        #region properties

        public virtual bool Disabled
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

        public DateTime LastModified
        {
            get { return _lastModified; }
            set { _lastModified = value; }
        }

        public virtual uint ExpiryTtl
        {
            get { return _expiryTtl; }
            set { _expiryTtl = value; }
        }

        public DateTime LastUsedOn
        {
            get { return _lastUsedOn; }
            set { _lastUsedOn = value; }
        }

        #endregion
    }
}
