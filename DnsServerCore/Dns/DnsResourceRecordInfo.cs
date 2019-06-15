/*
Technitium DNS Server
Copyright (C) 2019  Shreyas Zare (shreyas@technitium.com)

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

namespace DnsServerCore.Dns
{
    public class DnsResourceRecordInfo
    {
        #region variables

        readonly bool _disabled;

        #endregion

        #region constructor

        public DnsResourceRecordInfo()
        { }

        public DnsResourceRecordInfo(bool disabled)
        {
            _disabled = disabled;
        }

        public DnsResourceRecordInfo(BinaryReader bR)
        {
            switch (bR.ReadByte()) //version
            {
                case 1:
                    _disabled = bR.ReadBoolean();
                    break;

                default:
                    throw new NotSupportedException("DnsResourceRecordInfo format version not supported.");
            }
        }

        #endregion

        #region public

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write((byte)1); //version
            bW.Write(_disabled);
        }

        #endregion

        #region properties

        public bool Disabled
        { get { return _disabled; } }

        #endregion
    }
}
