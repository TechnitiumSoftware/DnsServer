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
using System.Net;
using System.Net.Mail;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Mail;

namespace Failover
{
    class EmailAlert : IDisposable
    {
        #region variables

        readonly HealthService _service;

        readonly string _name;
        bool _enabled;
        MailAddress[] _alertTo;
        string _smtpServer;
        int _smtpPort;
        bool _startTls;
        bool _smtpOverTls;
        string _username;
        string _password;
        MailAddress _mailFrom;

        readonly SmtpClientEx _smtpClient;

        #endregion

        #region constructor

        public EmailAlert(HealthService service, JsonElement jsonEmailAlert)
        {
            _service = service;

            _smtpClient = new SmtpClientEx();
            _smtpClient.DnsClient = new DnsClientInternal(_service.DnsServer);

            _name = jsonEmailAlert.GetPropertyValue("name", "default");

            Reload(jsonEmailAlert);
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
                if (_smtpClient is not null)
                    _smtpClient.Dispose();
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        #endregion

        #region private

        private async Task SendMailAsync(MailMessage message)
        {
            try
            {
                const int MAX_RETRIES = 3;
                const int WAIT_INTERVAL = 30000;

                for (int retries = 0; retries < MAX_RETRIES; retries++)
                {
                    try
                    {
                        await _smtpClient.SendMailAsync(message);
                        break;
                    }
                    catch
                    {
                        if (retries == MAX_RETRIES - 1)
                            throw;

                        await Task.Delay(WAIT_INTERVAL);
                    }
                }
            }
            catch (Exception ex)
            {
                _service.DnsServer.WriteLog("Failed to send email alert [" + _name + "].\r\n" + ex.ToString());
            }
        }

        #endregion

        #region public

        public void Reload(JsonElement jsonEmailAlert)
        {
            _enabled = jsonEmailAlert.GetPropertyValue("enabled", false);

            if (jsonEmailAlert.TryReadArray("alertTo", delegate (string emailAddress) { return new MailAddress(emailAddress); }, out MailAddress[] alertTo))
                _alertTo = alertTo;
            else
                _alertTo = null;

            _smtpServer = jsonEmailAlert.GetPropertyValue("smtpServer", null);
            _smtpPort = jsonEmailAlert.GetPropertyValue("smtpPort", 25);
            _startTls = jsonEmailAlert.GetPropertyValue("startTls", false);
            _smtpOverTls = jsonEmailAlert.GetPropertyValue("smtpOverTls", false);
            _username = jsonEmailAlert.GetPropertyValue("username", null);
            _password = jsonEmailAlert.GetPropertyValue("password", null);

            if (jsonEmailAlert.TryGetProperty("mailFrom", out JsonElement jsonMailFrom))
            {
                if (jsonEmailAlert.TryGetProperty("mailFromName", out JsonElement jsonMailFromName))
                    _mailFrom = new MailAddress(jsonMailFrom.GetString(), jsonMailFromName.GetString(), Encoding.UTF8);
                else
                    _mailFrom = new MailAddress(jsonMailFrom.GetString());
            }
            else
            {
                _mailFrom = null;
            }

            //update smtp client settings
            _smtpClient.Host = _smtpServer;
            _smtpClient.Port = _smtpPort;
            _smtpClient.EnableSsl = _startTls;
            _smtpClient.SmtpOverTls = _smtpOverTls;

            if (string.IsNullOrEmpty(_username))
                _smtpClient.Credentials = null;
            else
                _smtpClient.Credentials = new NetworkCredential(_username, _password);

            _smtpClient.Proxy = _service.DnsServer.Proxy;
        }

        public Task SendAlertAsync(IPAddress address, string healthCheck, HealthCheckResponse healthCheckResponse)
        {
            if (!_enabled || (_mailFrom is null) || (_alertTo is null) || (_alertTo.Length == 0))
                return Task.CompletedTask;

            MailMessage message = new MailMessage();

            message.From = _mailFrom;

            foreach (MailAddress alertTo in _alertTo)
                message.To.Add(alertTo);

            message.Subject = "[Alert] Address [" + address.ToString() + "] Status Is " + healthCheckResponse.Status.ToString().ToUpper();

            switch (healthCheckResponse.Status)
            {
                case HealthStatus.Failed:
                    message.Body = @"Hi,

The DNS Failover App was successfully able to perform a health check [" + healthCheck + "] on the address [" + address.ToString() + @"] and found that the address failed to respond. 

Address: " + address.ToString() + @"
Health Check: " + healthCheck + @"
Status: " + healthCheckResponse.Status.ToString().ToUpper() + @"
Alert Time: " + healthCheckResponse.DateTime.ToString("R") + @"
Failure Reason: " + healthCheckResponse.FailureReason + @"

Regards,
DNS Failover App
";
                    break;

                default:
                    message.Body = @"Hi,

The DNS Failover App was successfully able to perform a health check [" + healthCheck + "] on the address [" + address.ToString() + @"] and found that the address status was " + healthCheckResponse.Status.ToString().ToUpper() + @".

Address: " + address.ToString() + @"
Health Check: " + healthCheck + @"
Status: " + healthCheckResponse.Status.ToString().ToUpper() + @"
Alert Time: " + healthCheckResponse.DateTime.ToString("R") + @"

Regards,
DNS Failover App
";
                    break;
            }

            return SendMailAsync(message);
        }

        public Task SendAlertAsync(IPAddress address, string healthCheck, Exception ex)
        {
            if (!_enabled || (_mailFrom is null) || (_alertTo is null) || (_alertTo.Length == 0))
                return Task.CompletedTask;

            MailMessage message = new MailMessage();

            message.From = _mailFrom;

            foreach (MailAddress alertTo in _alertTo)
                message.To.Add(alertTo);

            message.Subject = "[Alert] Address [" + address.ToString() + "] Status Is ERROR";
            message.Body = @"Hi,

The DNS Failover App has failed to perform a health check [" + healthCheck + "] on the address [" + address.ToString() + @"]. 

Address: " + address.ToString() + @"
Health Check: " + healthCheck + @"
Status: ERROR
Alert Time: " + DateTime.UtcNow.ToString("R") + @"
Failure Reason: " + ex.ToString() + @"

Regards,
DNS Failover App
";

            return SendMailAsync(message);
        }

        public Task SendAlertAsync(string domain, DnsResourceRecordType type, string healthCheck, HealthCheckResponse healthCheckResponse)
        {
            if (!_enabled || (_mailFrom is null) || (_alertTo is null) || (_alertTo.Length == 0))
                return Task.CompletedTask;

            MailMessage message = new MailMessage();

            message.From = _mailFrom;

            foreach (MailAddress alertTo in _alertTo)
                message.To.Add(alertTo);

            message.Subject = "[Alert] Domain [" + domain + "] Status Is " + healthCheckResponse.Status.ToString().ToUpper();

            switch (healthCheckResponse.Status)
            {
                case HealthStatus.Failed:
                    message.Body = @"Hi,

The DNS Failover App was successfully able to perform a health check [" + healthCheck + "] on the domain name [" + domain + @"] and found that the domain name failed to respond. 

Domain: " + domain + @"
Record Type: " + type.ToString() + @"
Health Check: " + healthCheck + @"
Status: " + healthCheckResponse.Status.ToString().ToUpper() + @"
Alert Time: " + healthCheckResponse.DateTime.ToString("R") + @"
Failure Reason: " + healthCheckResponse.FailureReason + @"

Regards,
DNS Failover App
";
                    break;

                default:
                    message.Body = @"Hi,

The DNS Failover App was successfully able to perform a health check [" + healthCheck + "] on the domain name [" + domain + @"] and found that the domain name status was " + healthCheckResponse.Status.ToString().ToUpper() + @".

Domain: " + domain + @"
Record Type: " + type.ToString() + @"
Health Check: " + healthCheck + @"
Status: " + healthCheckResponse.Status.ToString().ToUpper() + @"
Alert Time: " + healthCheckResponse.DateTime.ToString("R") + @"

Regards,
DNS Failover App
";
                    break;
            }

            return SendMailAsync(message);
        }

        public Task SendAlertAsync(string domain, DnsResourceRecordType type, string healthCheck, Exception ex)
        {
            if (!_enabled || (_mailFrom is null) || (_alertTo is null) || (_alertTo.Length == 0))
                return Task.CompletedTask;

            MailMessage message = new MailMessage();

            message.From = _mailFrom;

            foreach (MailAddress alertTo in _alertTo)
                message.To.Add(alertTo);

            message.Subject = "[Alert] Domain [" + domain + "] Status Is ERROR";
            message.Body = @"Hi,

The DNS Failover App has failed to perform a health check [" + healthCheck + "] on the domain name [" + domain + @"]. 

Domain: " + domain + @"
Record Type: " + type.ToString() + @"
Health Check: " + healthCheck + @"
Status: ERROR
Alert Time: " + DateTime.UtcNow.ToString("R") + @"
Failure Reason: " + ex.ToString() + @"

Regards,
DNS Failover App
";

            return SendMailAsync(message);
        }

        #endregion

        #region properties

        public string Name
        { get { return _name; } }

        public bool Enabled
        { get { return _enabled; } }

        public MailAddress[] AlertTo
        { get { return _alertTo; } }

        public string SmtpServer
        { get { return _smtpServer; } }

        public int SmtpPort
        { get { return _smtpPort; } }

        public bool StartTls
        { get { return _startTls; } }

        public bool SmtpOverTls
        { get { return _smtpOverTls; } }

        public string Username
        { get { return _username; } }

        public string Password
        { get { return _password; } }

        public MailAddress MailFrom
        { get { return _mailFrom; } }

        #endregion

        class DnsClientInternal : IDnsClient
        {
            readonly IDnsServer _dnsServer;

            public DnsClientInternal(IDnsServer dnsServer)
            {
                _dnsServer = dnsServer;
            }

            public Task<DnsDatagram> ResolveAsync(DnsQuestionRecord question, CancellationToken cancellationToken = default)
            {
                return _dnsServer.DirectQueryAsync(question, cancellationToken: cancellationToken);
            }
        }
    }
}
