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

namespace DnsServerCore
{
    class UserSession
    {
        #region variables

        const int SESSION_TIMEOUT = 30 * 60 * 1000; //30 mins

        readonly string _username;
        DateTime _lastSeen;

        #endregion

        #region constructor

        public UserSession(string username)
        {
            _username = username;
            _lastSeen = DateTime.UtcNow;
        }

        #endregion

        #region public

        public void UpdateLastSeen()
        {
            _lastSeen = DateTime.UtcNow;
        }

        public bool HasExpired()
        {
            return _lastSeen.AddMilliseconds(SESSION_TIMEOUT) < DateTime.UtcNow;
        }

        #endregion

        #region properties

        public string Username
        { get { return _username; } }

        #endregion
    }
}
