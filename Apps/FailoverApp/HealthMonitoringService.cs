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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using TechnitiumLibrary.Net.Dns;

namespace Failover
{
    class HealthMonitoringService : IDisposable
    {
        #region variables

        static HealthMonitoringService _healthMonitoringService;

        readonly IDnsServer _dnsServer;

        readonly ConcurrentDictionary<string, HealthCheck> _healthChecks = new ConcurrentDictionary<string, HealthCheck>(1, 5);
        readonly ConcurrentDictionary<string, EmailAlert> _emailAlerts = new ConcurrentDictionary<string, EmailAlert>(1, 2);
        readonly ConcurrentDictionary<string, WebHook> _webHooks = new ConcurrentDictionary<string, WebHook>(1, 2);

        readonly ConcurrentDictionary<IPAddress, AddressMonitoring> _addressMonitoring = new ConcurrentDictionary<IPAddress, AddressMonitoring>();
        readonly ConcurrentDictionary<string, DomainMonitoring> _domainMonitoringA = new ConcurrentDictionary<string, DomainMonitoring>();
        readonly ConcurrentDictionary<string, DomainMonitoring> _domainMonitoringAAAA = new ConcurrentDictionary<string, DomainMonitoring>();

        readonly Timer _maintenanceTimer;
        const int MAINTENANCE_TIMER_INTERVAL = 15 * 60 * 1000; //15 mins

        #endregion

        #region constructor

        private HealthMonitoringService(IDnsServer dnsServer)
        {
            _dnsServer = dnsServer;

            _maintenanceTimer = new Timer(delegate (object state)
            {
                try
                {
                    foreach (KeyValuePair<IPAddress, AddressMonitoring> monitoring in _addressMonitoring)
                    {
                        if (monitoring.Value.IsExpired())
                        {
                            if (_addressMonitoring.TryRemove(monitoring.Key, out AddressMonitoring removedMonitoring))
                                removedMonitoring.Dispose();
                        }
                    }

                    foreach (KeyValuePair<string, DomainMonitoring> monitoring in _domainMonitoringA)
                    {
                        if (monitoring.Value.IsExpired())
                        {
                            if (_domainMonitoringA.TryRemove(monitoring.Key, out DomainMonitoring removedMonitoring))
                                removedMonitoring.Dispose();
                        }
                    }

                    foreach (KeyValuePair<string, DomainMonitoring> monitoring in _domainMonitoringAAAA)
                    {
                        if (monitoring.Value.IsExpired())
                        {
                            if (_domainMonitoringAAAA.TryRemove(monitoring.Key, out DomainMonitoring removedMonitoring))
                                removedMonitoring.Dispose();
                        }
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog(ex);
                }
                finally
                {
                    if (!_disposed)
                        _maintenanceTimer.Change(MAINTENANCE_TIMER_INTERVAL, Timeout.Infinite);
                }
            }, null, Timeout.Infinite, Timeout.Infinite);

            _maintenanceTimer.Change(MAINTENANCE_TIMER_INTERVAL, Timeout.Infinite);
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
                foreach (KeyValuePair<string, HealthCheck> healthCheck in _healthChecks)
                    healthCheck.Value.Dispose();

                _healthChecks.Clear();

                foreach (KeyValuePair<string, EmailAlert> emailAlert in _emailAlerts)
                    emailAlert.Value.Dispose();

                _emailAlerts.Clear();

                foreach (KeyValuePair<string, WebHook> webHook in _webHooks)
                    webHook.Value.Dispose();

                _webHooks.Clear();

                foreach (KeyValuePair<IPAddress, AddressMonitoring> monitoring in _addressMonitoring)
                    monitoring.Value.Dispose();

                _addressMonitoring.Clear();

                foreach (KeyValuePair<string, DomainMonitoring> monitoring in _domainMonitoringA)
                    monitoring.Value.Dispose();

                _domainMonitoringA.Clear();

                foreach (KeyValuePair<string, DomainMonitoring> monitoring in _domainMonitoringAAAA)
                    monitoring.Value.Dispose();

                _domainMonitoringAAAA.Clear();
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        #endregion

        #region static

        public static HealthMonitoringService Create(IDnsServer dnsServer)
        {
            if (_healthMonitoringService is null)
                _healthMonitoringService = new HealthMonitoringService(dnsServer);

            return _healthMonitoringService;
        }

        public void Initialize(dynamic jsonConfig)
        {
            //email alerts
            {
                //add or update email alerts
                foreach (dynamic jsonEmailAlert in jsonConfig.emailAlerts)
                {
                    string name;

                    if (jsonEmailAlert.name is null)
                        name = "default";
                    else
                        name = jsonEmailAlert.name.Value;

                    if (_emailAlerts.TryGetValue(name, out EmailAlert existingEmailAlert))
                    {
                        //update
                        existingEmailAlert.Reload(jsonEmailAlert);
                    }
                    else
                    {
                        //add
                        EmailAlert emailAlert = new EmailAlert(this, jsonEmailAlert);

                        _emailAlerts.TryAdd(emailAlert.Name, emailAlert);
                    }
                }

                //remove email alerts that dont exists in config
                foreach (KeyValuePair<string, EmailAlert> emailAlert in _emailAlerts)
                {
                    bool emailAlertExists = false;

                    foreach (dynamic jsonEmailAlert in jsonConfig.emailAlerts)
                    {
                        string name;

                        if (jsonEmailAlert.name is null)
                            name = "default";
                        else
                            name = jsonEmailAlert.name.Value;

                        if (name == emailAlert.Key)
                        {
                            emailAlertExists = true;
                            break;
                        }
                    }

                    if (!emailAlertExists)
                    {
                        if (_emailAlerts.TryRemove(emailAlert.Key, out EmailAlert removedEmailAlert))
                            removedEmailAlert.Dispose();
                    }
                }
            }

            //web hooks
            {
                //add or update email alerts
                foreach (dynamic jsonWebHook in jsonConfig.webHooks)
                {
                    string name;

                    if (jsonWebHook.name is null)
                        name = "default";
                    else
                        name = jsonWebHook.name.Value;

                    if (_webHooks.TryGetValue(name, out WebHook existingWebHook))
                    {
                        //update
                        existingWebHook.Reload(jsonWebHook);
                    }
                    else
                    {
                        //add
                        WebHook webHook = new WebHook(this, jsonWebHook);

                        _webHooks.TryAdd(webHook.Name, webHook);
                    }
                }

                //remove email alerts that dont exists in config
                foreach (KeyValuePair<string, WebHook> webHook in _webHooks)
                {
                    bool webHookExists = false;

                    foreach (dynamic jsonWebHook in jsonConfig.webHooks)
                    {
                        string name;

                        if (jsonWebHook.name is null)
                            name = "default";
                        else
                            name = jsonWebHook.name.Value;

                        if (name == webHook.Key)
                        {
                            webHookExists = true;
                            break;
                        }
                    }

                    if (!webHookExists)
                    {
                        if (_webHooks.TryRemove(webHook.Key, out WebHook removedWebHook))
                            removedWebHook.Dispose();
                    }
                }
            }

            //health checks
            {
                //add or update health checks
                foreach (dynamic jsonHealthCheck in jsonConfig.healthChecks)
                {
                    string name;

                    if (jsonHealthCheck.name is null)
                        name = "default";
                    else
                        name = jsonHealthCheck.name.Value;

                    if (_healthChecks.TryGetValue(name, out HealthCheck existingHealthCheck))
                    {
                        //update
                        existingHealthCheck.Reload(jsonHealthCheck);
                    }
                    else
                    {
                        //add
                        HealthCheck healthCheck = new HealthCheck(this, jsonHealthCheck);

                        _healthChecks.TryAdd(healthCheck.Name, healthCheck);
                    }
                }

                //remove health checks that dont exists in config
                foreach (KeyValuePair<string, HealthCheck> healthCheck in _healthChecks)
                {
                    bool healthCheckExists = false;

                    foreach (dynamic jsonHealthCheck in jsonConfig.healthChecks)
                    {
                        string name;

                        if (jsonHealthCheck.name is null)
                            name = "default";
                        else
                            name = jsonHealthCheck.name.Value;

                        if (name == healthCheck.Key)
                        {
                            healthCheckExists = true;
                            break;
                        }
                    }

                    if (!healthCheckExists)
                    {
                        if (_healthChecks.TryRemove(healthCheck.Key, out HealthCheck removedHealthCheck))
                        {
                            //remove health monitors using this health check
                            foreach (KeyValuePair<IPAddress, AddressMonitoring> monitoring in _addressMonitoring)
                                monitoring.Value.RemoveHealthMonitor(healthCheck.Key);

                            foreach (KeyValuePair<string, DomainMonitoring> monitoring in _domainMonitoringA)
                                monitoring.Value.RemoveHealthMonitor(healthCheck.Key);

                            foreach (KeyValuePair<string, DomainMonitoring> monitoring in _domainMonitoringAAAA)
                                monitoring.Value.RemoveHealthMonitor(healthCheck.Key);

                            removedHealthCheck.Dispose();
                        }
                    }
                }
            }
        }

        #endregion

        #region public

        public HealthCheckStatus QueryStatus(IPAddress address, string healthCheck, bool tryAdd)
        {
            if (_addressMonitoring.TryGetValue(address, out AddressMonitoring monitoring))
            {
                return monitoring.QueryStatus(healthCheck);
            }
            else if (tryAdd)
            {
                monitoring = new AddressMonitoring(this, address, healthCheck);

                if (!_addressMonitoring.TryAdd(address, monitoring))
                    monitoring.Dispose(); //failed to add first
            }

            return null;
        }

        public HealthCheckStatus QueryStatus(string domain, DnsResourceRecordType type, string healthCheck, bool tryAdd)
        {
            domain = domain.ToLower();

            switch (type)
            {
                case DnsResourceRecordType.A:
                    {
                        if (_domainMonitoringA.TryGetValue(domain, out DomainMonitoring monitoring))
                        {
                            return monitoring.QueryStatus(healthCheck);
                        }
                        else if (tryAdd)
                        {
                            monitoring = new DomainMonitoring(this, domain, type, healthCheck);

                            if (!_domainMonitoringA.TryAdd(domain, monitoring))
                                monitoring.Dispose(); //failed to add first
                        }
                    }
                    break;

                case DnsResourceRecordType.AAAA:
                    {
                        if (_domainMonitoringAAAA.TryGetValue(domain, out DomainMonitoring monitoring))
                        {
                            return monitoring.QueryStatus(healthCheck);
                        }
                        else if (tryAdd)
                        {
                            monitoring = new DomainMonitoring(this, domain, type, healthCheck);

                            if (!_domainMonitoringAAAA.TryAdd(domain, monitoring))
                                monitoring.Dispose(); //failed to add first
                        }
                    }
                    break;
            }

            return null;
        }

        #endregion

        #region properties

        internal IReadOnlyDictionary<string, HealthCheck> HealthChecks
        { get { return _healthChecks; } }

        internal IReadOnlyDictionary<string, EmailAlert> EmailAlerts
        { get { return _emailAlerts; } }

        internal IReadOnlyDictionary<string, WebHook> WebHooks
        { get { return _webHooks; } }

        internal IDnsServer DnsServer
        { get { return _dnsServer; } }

        #endregion
    }
}
