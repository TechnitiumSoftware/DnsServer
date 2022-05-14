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

using DnsServerCore.Dns.Zones;
using System;
using System.Collections.Generic;
using System.Threading;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Trees
{
    class AuthZoneNode : IDisposable
    {
        #region variables

        SubDomainZone _parentSideZone;
        ApexZone _apexZone;

        #endregion

        #region constructors

        public AuthZoneNode(SubDomainZone parentSideZone, ApexZone zone)
        {
            _parentSideZone = parentSideZone;
            _apexZone = zone;
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            if (_apexZone is not null)
                _apexZone.Dispose();

            _disposed = true;
        }

        #endregion

        #region public

        public bool TryAdd(ApexZone apexZone)
        {
            return Interlocked.CompareExchange(ref _apexZone, apexZone, null) is null;
        }

        public bool TryAdd(SubDomainZone parentSideZone)
        {
            return Interlocked.CompareExchange(ref _parentSideZone, parentSideZone, null) is null;
        }

        public bool TryRemove(out ApexZone apexZone)
        {
            apexZone = _apexZone;
            return ReferenceEquals(Interlocked.CompareExchange(ref _apexZone, null, apexZone), apexZone);
        }

        public bool TryRemove(out SubDomainZone parentSideZone)
        {
            parentSideZone = _parentSideZone;
            return ReferenceEquals(Interlocked.CompareExchange(ref _parentSideZone, null, parentSideZone), parentSideZone);
        }

        public SubDomainZone GetOrAddParentSideZone(Func<SubDomainZone> valueFactory)
        {
            SubDomainZone newParentSideZone = null;

            while (true)
            {
                SubDomainZone parentSideZone = _parentSideZone;
                if (parentSideZone is not null)
                    return parentSideZone;

                if (newParentSideZone is null)
                    newParentSideZone = valueFactory();

                if (TryAdd(newParentSideZone))
                    return newParentSideZone;
            }
        }

        public IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type, bool dnssecOk)
        {
            if ((_apexZone is null) || (type == DnsResourceRecordType.DS))
            {
                if (_parentSideZone is null)
                    return Array.Empty<DnsResourceRecord>();

                return _parentSideZone.QueryRecords(type, dnssecOk);
            }

            return _apexZone.QueryRecords(type, dnssecOk);
        }

        public AuthZone GetAuthZone(string zoneName)
        {
            if ((_apexZone is not null) && _apexZone.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                return _apexZone;

            return _parentSideZone;
        }

        #endregion

        #region properties

        public string Name
        {
            get
            {
                if (_parentSideZone is not null)
                    return _parentSideZone.Name;

                if (_apexZone is not null)
                    return _apexZone.Name;

                return null;
            }
        }

        public SubDomainZone ParentSideZone
        { get { return _parentSideZone; } }

        public ApexZone ApexZone
        { get { return _apexZone; } }

        public bool IsActive
        {
            get
            {
                if (_apexZone is not null)
                    return _apexZone.IsActive;

                if (_parentSideZone is not null)
                    return _parentSideZone.IsActive;

                return false;
            }
        }

        #endregion
    }
}
