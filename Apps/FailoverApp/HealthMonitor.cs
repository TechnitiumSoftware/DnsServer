/*
Technitium DNS Server
Copyright (C) 2023  Shreyas Zare (shreyas@technitium.com)

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
using System.Net;
using System.Threading;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace Failover
{
    class HealthMonitor : IDisposable
    {
        #region variables

        readonly IDnsServer _dnsServer;
        readonly IPAddress _address;
        readonly string _domain;
        readonly DnsResourceRecordType _type;
        readonly HealthCheck _healthCheck;

        readonly Timer _healthCheckTimer;
        const int HEALTH_CHECK_TIMER_INITIAL_INTERVAL = 1000;

        HealthCheckResponse _lastHealthCheckResponse;

        const int MONITOR_EXPIRY = 1 * 60 * 60 * 1000; //1 hour
        DateTime _lastHealthStatusCheckedOn;

        #endregion

        #region constructor

        public HealthMonitor(IDnsServer dnsServer, IPAddress address, HealthCheck healthCheck, Uri healthCheckUrl)
        {
            _dnsServer = dnsServer;
            _address = address;
            _healthCheck = healthCheck;

            _healthCheckTimer = new Timer(async delegate (object state)
            {
                try
                {
                    if (_healthCheck is null)
                    {
                        _lastHealthCheckResponse = null;
                    }
                    else
                    {
                        HealthCheckResponse healthCheckResponse = await _healthCheck.IsHealthyAsync(_address, healthCheckUrl);

                        bool statusChanged = false;
                        bool maintenance = false;

                        if (_lastHealthCheckResponse is null)
                        {
                            switch (healthCheckResponse.Status)
                            {
                                case HealthStatus.Failed:
                                    statusChanged = true;
                                    break;

                                case HealthStatus.Maintenance:
                                    statusChanged = true;
                                    maintenance = true;
                                    break;
                            }
                        }
                        else
                        {
                            if (_lastHealthCheckResponse.Status != healthCheckResponse.Status)
                            {
                                statusChanged = true;

                                if ((_lastHealthCheckResponse.Status == HealthStatus.Maintenance) || (healthCheckResponse.Status == HealthStatus.Maintenance))
                                    maintenance = true;
                            }
                        }

                        if (statusChanged)
                        {
                            switch (healthCheckResponse.Status)
                            {
                                case HealthStatus.Failed:
                                    _dnsServer.WriteLog("ALERT! Address [" + _address.ToString() + "] status is FAILED based on '" + _healthCheck.Name + "' health check. The failure reason is: " + healthCheckResponse.FailureReason);
                                    break;

                                default:
                                    _dnsServer.WriteLog("ALERT! Address [" + _address.ToString() + "] status is " + healthCheckResponse.Status.ToString().ToUpper() + " based on '" + _healthCheck.Name + "' health check.");
                                    break;
                            }

                            if (healthCheckResponse.Exception is not null)
                                _dnsServer.WriteLog(healthCheckResponse.Exception);

                            if (!maintenance)
                            {
                                //avoid sending email alerts when switching from or to maintenance
                                EmailAlert emailAlert = _healthCheck.EmailAlert;
                                if (emailAlert is not null)
                                    _ = emailAlert.SendAlertAsync(_address, _healthCheck.Name, healthCheckResponse);
                            }

                            WebHook webHook = _healthCheck.WebHook;
                            if (webHook is not null)
                                _ = webHook.CallAsync(_address, _healthCheck.Name, healthCheckResponse);
                        }

                        _lastHealthCheckResponse = healthCheckResponse;
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog(ex);

                    if (_lastHealthCheckResponse is null)
                    {
                        EmailAlert emailAlert = _healthCheck.EmailAlert;
                        if (emailAlert is not null)
                            _ = emailAlert.SendAlertAsync(_address, _healthCheck.Name, ex);

                        WebHook webHook = _healthCheck.WebHook;
                        if (webHook is not null)
                            _ = webHook.CallAsync(_address, _healthCheck.Name, ex);

                        _lastHealthCheckResponse = new HealthCheckResponse(HealthStatus.Failed, ex.ToString(), ex);
                    }
                    else
                    {
                        _lastHealthCheckResponse = null;
                    }
                }
                finally
                {
                    if (!_disposed && (_healthCheck is not null))
                        _healthCheckTimer.Change(_healthCheck.Interval, Timeout.Infinite);
                }
            }, null, Timeout.Infinite, Timeout.Infinite);

            _healthCheckTimer.Change(HEALTH_CHECK_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
        }

        public HealthMonitor(IDnsServer dnsServer, string domain, DnsResourceRecordType type, HealthCheck healthCheck, Uri healthCheckUrl)
        {
            _dnsServer = dnsServer;
            _domain = domain;
            _type = type;
            _healthCheck = healthCheck;

            _healthCheckTimer = new Timer(async delegate (object state)
            {
                try
                {
                    if (_healthCheck is null)
                    {
                        _lastHealthCheckResponse = null;
                    }
                    else
                    {
                        HealthCheckResponse healthCheckResponse = await _healthCheck.IsHealthyAsync(_domain, _type, healthCheckUrl);

                        bool statusChanged = false;
                        bool maintenance = false;

                        if (_lastHealthCheckResponse is null)
                        {
                            switch (healthCheckResponse.Status)
                            {
                                case HealthStatus.Failed:
                                    statusChanged = true;
                                    break;

                                case HealthStatus.Maintenance:
                                    statusChanged = true;
                                    maintenance = true;
                                    break;
                            }
                        }
                        else
                        {
                            if (_lastHealthCheckResponse.Status != healthCheckResponse.Status)
                            {
                                statusChanged = true;

                                if ((_lastHealthCheckResponse.Status == HealthStatus.Maintenance) || (healthCheckResponse.Status == HealthStatus.Maintenance))
                                    maintenance = true;
                            }
                        }

                        if (statusChanged)
                        {
                            switch (healthCheckResponse.Status)
                            {
                                case HealthStatus.Failed:
                                    _dnsServer.WriteLog("ALERT! Domain [" + _domain + "] type [" + _type.ToString() + "] status is FAILED based on '" + _healthCheck.Name + "' health check. The failure reason is: " + healthCheckResponse.FailureReason);
                                    break;

                                default:
                                    _dnsServer.WriteLog("ALERT! Domain [" + _domain + "] type [" + _type.ToString() + "] status is " + healthCheckResponse.Status.ToString().ToUpper() + " based on '" + _healthCheck.Name + "' health check.");
                                    break;
                            }

                            if (healthCheckResponse.Exception is not null)
                                _dnsServer.WriteLog(healthCheckResponse.Exception);

                            if (!maintenance)
                            {
                                //avoid sending email alerts when switching from or to maintenance
                                EmailAlert emailAlert = _healthCheck.EmailAlert;
                                if (emailAlert is not null)
                                    _ = emailAlert.SendAlertAsync(_domain, _type, _healthCheck.Name, healthCheckResponse);
                            }

                            WebHook webHook = _healthCheck.WebHook;
                            if (webHook is not null)
                                _ = webHook.CallAsync(_domain, _type, _healthCheck.Name, healthCheckResponse);
                        }

                        _lastHealthCheckResponse = healthCheckResponse;
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog(ex);

                    if (_lastHealthCheckResponse is null)
                    {
                        EmailAlert emailAlert = _healthCheck.EmailAlert;
                        if (emailAlert is not null)
                            _ = emailAlert.SendAlertAsync(_domain, _type, _healthCheck.Name, ex);

                        WebHook webHook = _healthCheck.WebHook;
                        if (webHook is not null)
                            _ = webHook.CallAsync(_domain, _type, _healthCheck.Name, ex);

                        _lastHealthCheckResponse = new HealthCheckResponse(HealthStatus.Failed, ex.ToString(), ex);
                    }
                    else
                    {
                        _lastHealthCheckResponse = null;
                    }
                }
                finally
                {
                    if (!_disposed && (_healthCheck is not null))
                        _healthCheckTimer.Change(_healthCheck.Interval, Timeout.Infinite);
                }
            }, null, Timeout.Infinite, Timeout.Infinite);

            _healthCheckTimer.Change(HEALTH_CHECK_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
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
                if (_healthCheckTimer is not null)
                    _healthCheckTimer.Dispose();
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

        public bool IsExpired()
        {
            return DateTime.UtcNow > _lastHealthStatusCheckedOn.AddMilliseconds(MONITOR_EXPIRY);
        }

        public void SetUnderMaintenance()
        {
            _lastHealthCheckResponse = new HealthCheckResponse(HealthStatus.Maintenance);
        }

        #endregion

        #region properties

        public IPAddress Address
        { get { return _address; } }

        public HealthCheckResponse LastHealthCheckResponse
        {
            get
            {
                _lastHealthStatusCheckedOn = DateTime.UtcNow;

                if (_lastHealthCheckResponse is null)
                    return new HealthCheckResponse(HealthStatus.Unknown);

                return _lastHealthCheckResponse;
            }
        }

        #endregion
    }
}
