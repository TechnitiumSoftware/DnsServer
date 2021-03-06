/*
Technitium DNS Server
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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

using DnsApplicationCommon;
using System;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Proxy;

namespace DnsServerCore.Dns.Applications
{
    class DnsServerInternal : IDnsServer
    {
        #region variables

        readonly DnsServer _dnsServer;
        readonly string _appName;
        readonly string _applicationFolder;

        #endregion

        #region constructor

        public DnsServerInternal(DnsServer dnsServer, string appName, string applicationFolder)
        {
            _dnsServer = dnsServer;
            _appName = appName;
            _applicationFolder = applicationFolder;
        }

        #endregion

        public Task<DnsDatagram> DirectQueryAsync(DnsQuestionRecord question, int timeout = 2000)
        {
            return _dnsServer.DirectQueryAsync(question, timeout);
        }

        public void WriteLog(string message)
        {
            LogManager log = _dnsServer.LogManager;
            if (log != null)
                log.Write("DNS App [" + _appName + "]: " + message);
        }

        public void WriteLog(Exception ex)
        {
            LogManager log = _dnsServer.LogManager;
            if (log != null)
                log.Write("DNS App [" + _appName + "]: " + ex.ToString());
        }

        public string ServerDomain
        { get { return _dnsServer.ServerDomain; } }

        public string ApplicationFolder
        { get { return _applicationFolder; } }

        public IDnsCache DnsCache
        { get { return _dnsServer.DnsCache; } }

        public NetProxy Proxy
        { get { return _dnsServer.Proxy; } }

        public bool PreferIPv6
        { get { return _dnsServer.PreferIPv6; } }
    }
}
