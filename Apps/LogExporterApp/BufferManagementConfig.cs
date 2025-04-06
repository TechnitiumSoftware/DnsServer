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
using System.Text.Json;
using System.Text.Json.Serialization;

namespace LogExporter
{
    public class BufferManagementConfig
    {
        [JsonPropertyName("maxQueueSize")]
        public int MaxQueueSize
        { get; set; }

        [JsonPropertyName("file")]
        public FileTarget? FileTarget { get; set; }

        [JsonPropertyName("http")]
        public HttpTarget? HttpTarget { get; set; }

        [JsonPropertyName("syslog")]
        public SyslogTarget? SyslogTarget { get; set; }

        // Load configuration from JSON
        public static BufferManagementConfig? Deserialize(string json)
        {
            return JsonSerializer.Deserialize<BufferManagementConfig>(json, DnsConfigSerializerOptions.Default);
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
        public required string Address { get; set; }

        [JsonPropertyName("port")]
        public int? Port { get; set; }

        [JsonPropertyName("protocol")]
        public string? Protocol { get; set; }
    }

    public class FileTarget : TargetBase
    {
        [JsonPropertyName("path")]
        public required string Path { get; set; }
    }

    public class HttpTarget : TargetBase
    {
        [JsonPropertyName("endpoint")]
        public required string Endpoint { get; set; }

        [JsonPropertyName("headers")]
        public Dictionary<string, string?>? Headers { get; set; }
    }

    // Setup reusable options with a single instance
    public static class DnsConfigSerializerOptions
    {
        public static readonly JsonSerializerOptions Default = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase, // Convert properties to camelCase
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping, // For safe encoding
            NumberHandling = JsonNumberHandling.Strict,
            AllowTrailingCommas = true, // Allow trailing commas in JSON
            DictionaryKeyPolicy = JsonNamingPolicy.CamelCase, // Convert dictionary keys to camelCase
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull // Ignore null values
        };
    }
}
