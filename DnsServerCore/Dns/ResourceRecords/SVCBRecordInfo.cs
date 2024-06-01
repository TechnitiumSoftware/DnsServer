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

using System.IO;

namespace DnsServerCore.Dns.ResourceRecords
{
    class SVCBRecordInfo : GenericRecordInfo
    {
        #region variables

        bool _autoIpv4Hint;
        bool _autoIpv6Hint;

        #endregion

        #region constructor

        public SVCBRecordInfo()
        { }

        public SVCBRecordInfo(BinaryReader bR)
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
                    _autoIpv4Hint = bR.ReadBoolean();
                    _autoIpv6Hint = bR.ReadBoolean();
                    break;

                default:
                    throw new InvalidDataException("SVCBRecordInfo format version not supported.");
            }
        }

        protected override void WriteExtendedRecordInfoTo(BinaryWriter bW)
        {
            bW.Write((byte)1); //version

            bW.Write(_autoIpv4Hint);
            bW.Write(_autoIpv6Hint);
        }

        #endregion

        #region properties

        public bool AutoIpv4Hint
        {
            get { return _autoIpv4Hint; }
            set { _autoIpv4Hint = value; }
        }

        public bool AutoIpv6Hint
        {
            get { return _autoIpv6Hint; }
            set { _autoIpv6Hint = value; }
        }

        #endregion
    }
}
