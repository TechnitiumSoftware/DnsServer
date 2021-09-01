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

namespace Failover
{
    enum HealthStatus
    {
        Unknown = 0,
        Failed = 1,
        Healthy = 2,
        Maintenance = 3
    }

    class HealthCheckResponse
    {
        #region variables

        public readonly DateTime DateTime = DateTime.UtcNow;
        public readonly HealthStatus Status;
        public readonly string FailureReason;
        public readonly Exception Exception;

        #endregion

        #region constructor

        public HealthCheckResponse(HealthStatus status, string failureReason = null, Exception exception = null)
        {
            Status = status;
            FailureReason = failureReason;
            Exception = exception;
        }

        #endregion
    }
}
