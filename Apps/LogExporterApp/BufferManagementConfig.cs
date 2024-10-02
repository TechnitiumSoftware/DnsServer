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

using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace LogExporter
{
    public class BufferManagementConfig
    {
        [JsonPropertyName("maxLogEntries")]
        public int? MaxLogEntries { get; set; }

        [JsonPropertyName("file")]
        public FileTarget? FileTarget { get; set; }

        [JsonPropertyName("http")]
        public HttpTarget? HttpTarget { get; set; }

        [JsonPropertyName("syslog")]
        public SyslogTarget? SyslogTarget { get; set; }

        // Load configuration from JSON
        public static BufferManagementConfig? Deserialize(string json)
        {
            return JsonSerializer.Deserialize<BufferManagementConfig>(json);
        }
    }

    public class TargetBase
    {
        [JsonPropertyName("enabled")]
        public bool Enabled { get; set; }
    }

    public class SyslogTarget : TargetBase
    {
        [JsonPropertyName("address")]
        public string Address { get; set; }

        [JsonPropertyName("port")]
        public int? Port { get; set; }

        [JsonPropertyName("protocol")]
        public string? Protocol { get; set; }
    }

    public class FileTarget : TargetBase
    {
        [JsonPropertyName("path")]
        public string Path { get; set; }
    }

    public class HttpTarget : TargetBase
    {
        [JsonPropertyName("endpoint")]
        public string Endpoint { get; set; }

        [JsonPropertyName("method")]
        public string Method { get; set; }

        [JsonPropertyName("headers")]
        public Dictionary<string, string>? Headers { get; set; }
    }
}
