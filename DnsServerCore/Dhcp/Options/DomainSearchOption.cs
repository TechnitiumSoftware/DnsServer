/*
Technitium DNS Server
Copyright (C) 2022  Shreyas Zare (shreyas@technitium.com)

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

using System.Collections.Generic;
using System.IO;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Dhcp.Options
{
    class DomainSearchOption : DhcpOption
    {
        #region variables

        IReadOnlyCollection<string> _searchStrings;

        #endregion

        #region constructor

        public DomainSearchOption(IReadOnlyCollection<string> searchStrings)
            : base(DhcpOptionCode.DomainSearch)
        {
            _searchStrings = searchStrings;
        }

        public DomainSearchOption(Stream s)
            : base(DhcpOptionCode.DomainSearch, s)
        { }

        #endregion

        #region protected

        protected override void ParseOptionValue(Stream s)
        {
            if (s.Length < 1)
                throw new InvalidDataException();

            List<string> searchStrings = new List<string>();

            while (s.Length > 0)
                searchStrings.Add(DnsDatagram.DeserializeDomainName(s));

            _searchStrings = searchStrings;
        }

        protected override void WriteOptionValue(Stream s)
        {
            List<DnsDomainOffset> domainEntries = new List<DnsDomainOffset>(1);

            foreach (string searchString in _searchStrings)
                DnsDatagram.SerializeDomainName(searchString, s, domainEntries);
        }

        #endregion

        #region properties

        public IReadOnlyCollection<string> SearchStrings
        { get { return _searchStrings; } }

        #endregion
    }
}
