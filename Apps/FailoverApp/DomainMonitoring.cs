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

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using TechnitiumLibrary.Net.Dns;

namespace Failover
{
    class DomainMonitoring : IDisposable
    {
        #region variables

        readonly HealthMonitoringService _service;
        readonly string _domain;
        readonly DnsResourceRecordType _type;

        readonly ConcurrentDictionary<string, HealthMonitor> _healthMonitors = new ConcurrentDictionary<string, HealthMonitor>(1, 1);

        #endregion

        #region constructor

        public DomainMonitoring(HealthMonitoringService service, string domain, DnsResourceRecordType type, string healthCheck)
        {
            _service = service;
            _domain = domain;
            _type = type;

            if (_service.HealthChecks.TryGetValue(healthCheck, out HealthCheck existingHealthCheck))
                _healthMonitors.TryAdd(healthCheck, new HealthMonitor(_service.DnsServer, domain, type, existingHealthCheck));
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
                foreach (KeyValuePair<string, HealthMonitor> healthMonitor in _healthMonitors)
                    healthMonitor.Value.Dispose();

                _healthMonitors.Clear();
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

        public HealthCheckStatus QueryStatus(string healthCheck)
        {
            if (_healthMonitors.TryGetValue(healthCheck, out HealthMonitor monitor))
                return monitor.HealthCheckStatus;

            if (_service.HealthChecks.TryGetValue(healthCheck, out HealthCheck existingHealthCheck))
                _healthMonitors.TryAdd(healthCheck, new HealthMonitor(_service.DnsServer, _domain, _type, existingHealthCheck));

            return null;
        }

        public void RemoveHealthMonitor(string healthCheck)
        {
            if (_healthMonitors.TryRemove(healthCheck, out HealthMonitor removedMonitor))
                removedMonitor.Dispose();
        }

        public bool IsExpired()
        {
            foreach (KeyValuePair<string, HealthMonitor> healthMonitor in _healthMonitors)
            {
                if (healthMonitor.Value.IsExpired())
                {
                    if (_healthMonitors.TryRemove(healthMonitor.Key, out HealthMonitor removedMonitor))
                        removedMonitor.Dispose();
                }
            }

            return _healthMonitors.IsEmpty;
        }

        #endregion

        #region property

        public string Domain
        { get { return _domain; } }

        public DnsResourceRecordType Type
        { get { return _type; } }

        #endregion
    }
}
