/*
Technitium DNS Server
Copyright (C) 2020  Shreyas Zare (shreyas@technitium.com)

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
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Dns
{
    class ResolverTask
    {
        #region variables

        readonly DateTime _createdOn;
        readonly TaskCompletionSource<DnsDatagram> _taskCompletionSource;

        #endregion

        #region constructor

        public ResolverTask()
        {
            _createdOn = DateTime.UtcNow;
            _taskCompletionSource = new TaskCompletionSource<DnsDatagram>();
        }

        #endregion

        #region public

        public bool IsStuck(int timeout)
        {
            return (DateTime.UtcNow - _createdOn).TotalMilliseconds > timeout;
        }

        #endregion

        #region properties

        public TaskCompletionSource<DnsDatagram> TaskCompletionSource
        { get { return _taskCompletionSource; } }

        #endregion
    }
}
