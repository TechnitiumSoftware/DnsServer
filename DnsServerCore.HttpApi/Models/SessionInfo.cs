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

using System.Collections.Generic;

namespace DnsServerCore.HttpApi.Models
{
    public class SessionInfo
    {
        public string? DisplayName { get; set; }
        public required string Username { get; set; }
        public bool? TotpEnabled { get; set; }
        public string? TokenName { get; set; }
        public required string Token { get; set; }
        public DetailedInfo? Info { get; set; }

        public class DetailedInfo
        {
            public required string Version { get; set; }
            public required string UpTimeStamp { get; set; }
            public required string DnsServerDomain { get; set; }
            public required int DefaultRecordTtl { get; set; }
            public required bool UseSoaSerialDateScheme { get; set; }
            public required bool DnssecValidation { get; set; }
            public required Dictionary<string, PermissionInfo> Permissions { get; set; }
        }

        public class PermissionInfo
        {
            public required bool CanView { get; set; }
            public required bool CanModify { get; set; }
            public required bool CanDelete { get; set; }
        }
    }
}
