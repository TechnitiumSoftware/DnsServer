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

using DnsServerCore.ApplicationCommon;
using MaxMind.GeoIP2;
using System;
using System.IO;

namespace GeoDistance
{
    class MaxMind : IDisposable
    {
        #region variables

        static MaxMind _maxMind;

        readonly DatabaseReader _mmCityReader;
        readonly DatabaseReader _mmIspReader;
        readonly DatabaseReader _mmAsnReader;

        #endregion

        #region constructor

        private MaxMind(IDnsServer dnsServer)
        {
            string mmCityFile = Path.Combine(dnsServer.ApplicationFolder, "GeoIP2-City.mmdb");

            if (!File.Exists(mmCityFile))
                mmCityFile = Path.Combine(dnsServer.ApplicationFolder, "GeoLite2-City.mmdb");

            if (!File.Exists(mmCityFile))
                throw new FileNotFoundException("MaxMind City file is missing!");

            _mmCityReader = new DatabaseReader(mmCityFile);

            string mmIspFile = Path.Combine(dnsServer.ApplicationFolder, "GeoIP2-ISP.mmdb");
            if (File.Exists(mmIspFile))
            {
                _mmIspReader = new DatabaseReader(mmIspFile);
                return;
            }

            string mmAsnFile = Path.Combine(dnsServer.ApplicationFolder, "GeoLite2-ASN.mmdb");
            if (File.Exists(mmAsnFile))
                _mmAsnReader = new DatabaseReader(mmAsnFile);
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
                _mmCityReader?.Dispose();
                _mmIspReader?.Dispose();
                _mmAsnReader?.Dispose();
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

        public DatabaseReader CityReader
        { get { return _mmCityReader; } }

        public DatabaseReader IspReader
        { get { return _mmIspReader; } }

        public DatabaseReader AsnReader
        { get { return _mmAsnReader; } }

        #endregion
    }
}
