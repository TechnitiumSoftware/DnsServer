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

using DnsServerCore;
using Microsoft.Extensions.Hosting;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace DnsServerWindowsService
{
    public class DnsServiceWorker : BackgroundService
    {
        readonly DnsWebService _service;

        public DnsServiceWorker()
        {
            _service = new DnsWebService(null, new Uri("https://go.technitium.com/?id=43"), new Uri("https://go.technitium.com/?id=40"));
        }

        public override Task StartAsync(CancellationToken cancellationToken)
        {
            _service.Start();
            return Task.CompletedTask;
        }

        public override Task StopAsync(CancellationToken cancellationToken)
        {
            _service.Stop();
            return Task.CompletedTask;
        }

        public override void Dispose()
        {
            if (_service != null)
                _service.Dispose();
        }

        protected override Task ExecuteAsync(CancellationToken stoppingToken)
        {
            return Task.CompletedTask;
        }
    }
}
