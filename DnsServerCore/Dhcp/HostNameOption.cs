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
using System.Text;
using TechnitiumLibrary.IO;

namespace DnsServerCore.Dhcp
{
    class HostNameOption : DhcpOption
    {
        #region variables

        readonly string _hostName;

        #endregion

        #region constructor

        public HostNameOption(Stream s)
            : base(DhcpOptionCode.HostName)
        {
            int len = s.ReadByte();
            if (len < 0)
                throw new EndOfStreamException();

            if (len < 1)
                throw new InvalidDataException();

            _hostName = Encoding.ASCII.GetString(s.ReadBytes(len));
        }

        #endregion

        #region protected

        protected override void WriteOptionTo(Stream s)
        {
            s.WriteByte(Convert.ToByte(_hostName.Length));
            s.Write(Encoding.ASCII.GetBytes(_hostName));
        }

        #endregion

        #region properties

        public string HostName
        { get { return _hostName; } }

        #endregion
    }
}
