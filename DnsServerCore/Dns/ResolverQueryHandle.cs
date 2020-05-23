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

using System.Threading;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Dns
{
    class ResolverQueryHandle
    {
        #region variables

        DnsDatagram _response;
        readonly EventWaitHandle _waitHandle = new ManualResetEvent(false);

        #endregion

        #region public

        public void Set(DnsDatagram response)
        {
            _response = response;
            _waitHandle.Set();
        }

        public DnsDatagram WaitForResponse(int timeout)
        {
            _waitHandle.WaitOne(timeout);
            return _response;
        }

        #endregion
    }
}
