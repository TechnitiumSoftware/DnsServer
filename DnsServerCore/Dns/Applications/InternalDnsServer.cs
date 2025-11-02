/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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

using DnsServerCore.ApplicationCommon;
using System;
using System.Net.Mail;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Proxy;

namespace DnsServerCore.Dns.Applications
{
    class InternalDnsServer : IDnsServer
    {
        #region variables

        readonly DnsServer _dnsServer;
        readonly string _applicationName;
        readonly string _applicationFolder;

        IDnsCache _dnsCache;

        #endregion

        #region constructor

        public InternalDnsServer(DnsServer dnsServer, string applicationName, string applicationFolder)
        {
            _dnsServer = dnsServer;
            _applicationName = applicationName;
            _applicationFolder = applicationFolder;
        }

        #endregion

        #region public

        public Task<DnsDatagram> DirectQueryAsync(DnsQuestionRecord question, int timeout = 4000, CancellationToken cancellationToken = default)
        {
            return _dnsServer.DirectQueryAsync(question, timeout, true, cancellationToken);
        }

        public Task<DnsDatagram> DirectQueryAsync(DnsDatagram request, int timeout = 4000, CancellationToken cancellationToken = default)
        {
            return _dnsServer.DirectQueryAsync(request, timeout, true, cancellationToken);
        }

        public Task<DnsDatagram> ResolveAsync(DnsQuestionRecord question, CancellationToken cancellationToken = default)
        {
            return DirectQueryAsync(question, cancellationToken: cancellationToken);
        }

        public void WriteLog(string message)
        {
            _dnsServer.LogManager.Write("DNS App [" + _applicationName + "]: " + message);
        }

        public void WriteLog(Exception ex)
        {
            _dnsServer.LogManager.Write("DNS App [" + _applicationName + "]: " + ex.ToString());
        }

        #endregion

        #region properties

        public string ApplicationName
        { get { return _applicationName; } }

        public string ApplicationFolder
        { get { return _applicationFolder; } }

        public string ServerDomain
        { get { return _dnsServer.ServerDomain; } }

        public MailAddress ResponsiblePerson
        { get { return _dnsServer.ResponsiblePerson; } }

        public IDnsCache DnsCache
        {
            get
            {
                if (_dnsCache is null)
                    _dnsCache = new ResolverDnsCache(_dnsServer, true);

                return _dnsCache;
            }
        }

        public NetProxy Proxy
        { get { return _dnsServer.Proxy; } }

        public bool PreferIPv6
        { get { return _dnsServer.PreferIPv6; } }

        public ushort UdpPayloadSize
        { get { return _dnsServer.UdpPayloadSize; } }

        #endregion
    }
}
