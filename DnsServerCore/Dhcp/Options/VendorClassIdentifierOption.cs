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
using System.Text;
using TechnitiumLibrary.IO;

namespace DnsServerCore.Dhcp.Options
{
    class VendorClassIdentifierOption : DhcpOption
    {
        #region variables

        string _identifier;

        #endregion

        #region constructor

        public VendorClassIdentifierOption(string identifier)
            : base(DhcpOptionCode.VendorClassIdentifier)
        {
            _identifier = identifier;
        }

        public VendorClassIdentifierOption(Stream s)
            : base(DhcpOptionCode.VendorClassIdentifier, s)
        { }

        #endregion

        #region protected

        protected override void ParseOptionValue(Stream s)
        {
            _identifier = Encoding.ASCII.GetString(s.ReadExactly((int)s.Length));
        }

        protected override void WriteOptionValue(Stream s)
        {
            s.Write(Encoding.ASCII.GetBytes(_identifier));
        }

        #endregion

        #region properties

        public string Identifier
        { get { return _identifier; } }

        #endregion
    }
}
