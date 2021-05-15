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
using System.Net;
using System.Threading;
using TechnitiumLibrary.Net.Dns;

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

        HealthCheckStatus _healthCheckStatus;

        const int MONITOR_EXPIRY = 1 * 60 * 60 * 1000; //1 hour
        DateTime _lastStatusCheckedOn;

        #endregion

        #region constructor

        public HealthMonitor(IDnsServer dnsServer, IPAddress address, HealthCheck healthCheck)
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
                        _healthCheckStatus = null;
                    }
                    else
                    {
                        HealthCheckStatus healthCheckStatus = await _healthCheck.IsHealthyAsync(_address);

                        bool sendAlert = false;

                        if (_healthCheckStatus is null)
                        {
                            if (!healthCheckStatus.IsHealthy)
                                sendAlert = true;
                        }
                        else
                        {
                            if (_healthCheckStatus.IsHealthy != healthCheckStatus.IsHealthy)
                                sendAlert = true;
                            else if (_healthCheckStatus.FailureReason != healthCheckStatus.FailureReason)
                                sendAlert = true;
                        }

                        if (sendAlert)
                        {
                            EmailAlert emailAlert = _healthCheck.EmailAlert;
                            if (emailAlert is not null)
                                _ = emailAlert.SendAlertAsync(_address, _healthCheck.Name, healthCheckStatus);

                            WebHook webHook = _healthCheck.WebHook;
                            if (webHook is not null)
                                _ = webHook.CallAsync(_address, _healthCheck.Name, healthCheckStatus);
                        }

                        _healthCheckStatus = healthCheckStatus;
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog(ex);

                    if (_healthCheckStatus is null)
                    {
                        EmailAlert emailAlert = _healthCheck.EmailAlert;
                        if (emailAlert is not null)
                            _ = emailAlert.SendAlertAsync(_address, _healthCheck.Name, ex);

                        WebHook webHook = _healthCheck.WebHook;
                        if (webHook is not null)
                            _ = webHook.CallAsync(_address, _healthCheck.Name, ex);

                        _healthCheckStatus = new HealthCheckStatus(false, ex.ToString());
                    }
                    else
                    {
                        _healthCheckStatus = null;
                    }
                }
                finally
                {
                    if (!_disposed && (_healthCheck is not null))
                        _healthCheckTimer.Change(_healthCheck.Interval, Timeout.Infinite);
                }
            }, null, Timeout.Infinite, Timeout.Infinite);

            _healthCheckTimer.Change(0, Timeout.Infinite);
        }

        public HealthMonitor(IDnsServer dnsServer, string domain, DnsResourceRecordType type, HealthCheck healthCheck)
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
                        _healthCheckStatus = null;
                    }
                    else
                    {
                        HealthCheckStatus healthCheckStatus = await _healthCheck.IsHealthyAsync(_domain, _type);

                        bool sendAlert = false;

                        if (_healthCheckStatus is null)
                        {
                            if (!healthCheckStatus.IsHealthy)
                                sendAlert = true;
                        }
                        else
                        {
                            if (_healthCheckStatus.IsHealthy != healthCheckStatus.IsHealthy)
                                sendAlert = true;
                            else if (_healthCheckStatus.FailureReason != healthCheckStatus.FailureReason)
                                sendAlert = true;
                        }

                        if (sendAlert)
                        {
                            EmailAlert emailAlert = _healthCheck.EmailAlert;
                            if (emailAlert is not null)
                                _ = emailAlert.SendAlertAsync(_domain, _type, _healthCheck.Name, healthCheckStatus);

                            WebHook webHook = _healthCheck.WebHook;
                            if (webHook is not null)
                                _ = webHook.CallAsync(_domain, _type, _healthCheck.Name, healthCheckStatus);
                        }

                        _healthCheckStatus = healthCheckStatus;
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog(ex);

                    if (_healthCheckStatus is null)
                    {
                        EmailAlert emailAlert = _healthCheck.EmailAlert;
                        if (emailAlert is not null)
                            _ = emailAlert.SendAlertAsync(_domain, _type, _healthCheck.Name, ex);

                        WebHook webHook = _healthCheck.WebHook;
                        if (webHook is not null)
                            _ = webHook.CallAsync(_domain, _type, _healthCheck.Name, ex);

                        _healthCheckStatus = new HealthCheckStatus(false, ex.ToString());
                    }
                    else
                    {
                        _healthCheckStatus = null;
                    }
                }
                finally
                {
                    if (!_disposed && (_healthCheck is not null))
                        _healthCheckTimer.Change(_healthCheck.Interval, Timeout.Infinite);
                }
            }, null, Timeout.Infinite, Timeout.Infinite);

            _healthCheckTimer.Change(0, Timeout.Infinite);
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
            return DateTime.UtcNow > _lastStatusCheckedOn.AddMilliseconds(MONITOR_EXPIRY);
        }

        #endregion

        #region properties

        public HealthCheckStatus HealthCheckStatus
        {
            get
            {
                _lastStatusCheckedOn = DateTime.UtcNow;
                return _healthCheckStatus;
            }
        }

        #endregion
    }
}
