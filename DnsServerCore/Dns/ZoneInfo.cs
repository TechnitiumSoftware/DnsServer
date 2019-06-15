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

namespace DnsServerCore.Dns
{
    public class ZoneInfo : IComparable<ZoneInfo>
    {
        #region variables

        readonly string _zoneName;
        readonly bool _disabled;
        readonly bool _internal;

        #endregion

        #region constructor

        public ZoneInfo(string zoneName, bool disabled, bool @internal)
        {
            _zoneName = zoneName;
            _disabled = disabled;
            _internal = @internal;
        }

        #endregion

        #region public

        public int CompareTo(ZoneInfo other)
        {
            return this._zoneName.CompareTo(other._zoneName);
        }

        #endregion

        #region properties

        public string ZoneName
        { get { return _zoneName; } }

        public bool Disabled
        { get { return _disabled; } }

        public bool Internal
        { get { return _internal; } }

        #endregion
    }
}
