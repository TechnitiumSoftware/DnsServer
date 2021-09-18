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

using DnsServerCore.ApplicationCommon;
using MaxMind.GeoIP2;
using System;
using System.IO;

namespace GeoContinent
{
    class MaxMind : IDisposable
    {
        #region variables

        static MaxMind _maxMind;

        readonly DatabaseReader _mmCountryReader;

        #endregion

        #region constructor

        private MaxMind(IDnsServer dnsServer)
        {
            string mmFile = Path.Combine(dnsServer.ApplicationFolder, "GeoIP2-Country.mmdb");

            if (!File.Exists(mmFile))
                mmFile = Path.Combine(dnsServer.ApplicationFolder, "GeoLite2-Country.mmdb");

            if (!File.Exists(mmFile))
                throw new FileNotFoundException("MaxMind Country file is missing!");

            _mmCountryReader = new DatabaseReader(mmFile);
        }

        #endregion

        #region IDisposable

        bool _disposed;

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_mmCountryReader is not null)
                    _mmCountryReader.Dispose();
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        #endregion

        #region public

        public static MaxMind Create(IDnsServer dnsServer)
        {
            if (_maxMind is null)
                _maxMind = new MaxMind(dnsServer);

            return _maxMind;
        }

        #endregion

        #region properties

        public DatabaseReader DatabaseReader
        { get { return _mmCountryReader; } }

        #endregion
    }
}
