/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)
Copyright (C) 2025  Zafer Balkan (zafer@zaferbalkan.com)

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
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using System.Text.Json.Serialization;
using TechnitiumLibrary.Net.Dns;

namespace LogExporter
{
    public class AppConfig
    {
        [JsonPropertyName("maxQueueSize")]
        [Range(1, int.MaxValue, ErrorMessage = "maxQueueSize must be greater than zero.")]
        public int MaxQueueSize { get; set; }

        [JsonPropertyName("enableEdnsLogging")]
        public bool EnableEdnsLogging { get; set; }

        [JsonPropertyName("console")]
        public ConsoleTarget? ConsoleTarget { get; set; }

        [JsonPropertyName("file")]
        public FileTarget? FileTarget { get; set; }

        [JsonPropertyName("http")]
        public HttpTarget? HttpTarget { get; set; }

        [JsonPropertyName("syslog")]
        public SyslogTarget? SyslogTarget { get; set; }

        /// <summary>
        /// Loads config and enforces DataAnnotations validation.
        ///
        /// ADR: Validation is intentionally centralized here so that:
        ///   - App receives only a fully valid configuration.
        ///   - Errors surface early with domain-specific messages.
        ///   - No runtime failures occur deep inside the logging pipeline.
        /// This ensures plugin initialization is deterministic and safe.
        /// </summary>
        public static AppConfig Deserialize(string json)
        {
            var config = JsonSerializer.Deserialize<AppConfig>(json, DnsConfigSerializerOptions.Default)
                         ?? throw new DnsClientException("Configuration could not be deserialized.");

            ValidateObject(config);

            // Validate enabled targets only — disabled ones may be incomplete by design.
            if (config.FileTarget?.Enabled == true)
                ValidateObject(config.FileTarget);

            if (config.HttpTarget?.Enabled == true)
                ValidateObject(config.HttpTarget);

            if (config.SyslogTarget?.Enabled == true)
                ValidateObject(config.SyslogTarget);

            return config;
        }

        private static void ValidateObject(object instance)
        {
            var ctx = new ValidationContext(instance);
            Validator.ValidateObject(instance, ctx, validateAllProperties: true);
        }
    }

    public class TargetBase
    {
        [JsonPropertyName("enabled")]
        public bool Enabled { get; set; }
    }

    public class ConsoleTarget : TargetBase { }

    public class SyslogTarget : TargetBase
    {
        [JsonPropertyName("address")]
        [Required(ErrorMessage = "syslog.address is required when syslog logging is enabled.")]
        public string Address { get; set; } = string.Empty;

        [JsonPropertyName("port")]
        [Range(1, 65535)]
        public int? Port { get; set; }

        [JsonPropertyName("protocol")]
        [AllowedValues(["UDP", "TCP", "TLS", "LOCAL"])]
        public string? Protocol { get; set; }
    }

    public class FileTarget : TargetBase
    {
        [JsonPropertyName("path")]
        [Required(ErrorMessage = "file.path is required when file logging is enabled.")]
        public string Path { get; set; } = string.Empty;
    }

    public class HttpTarget : TargetBase
    {
        [JsonPropertyName("endpoint")]
        [Required(ErrorMessage = "http.endpoint is required when HTTP logging is enabled.")]
        [Url]
        public string Endpoint { get; set; } = string.Empty;

        [JsonPropertyName("headers")]
        public Dictionary<string, string?>? Headers { get; set; }
    }

    /// <summary>
    /// Shared serializer configuration for reading dnsApp.config.
    /// ADR: The serializer options are centralized so that parsing behavior
    /// is stable and predictable across the entire plugin lifetime.
    /// </summary>
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
