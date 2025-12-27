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

using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using System.Text.Json.Serialization;
using TechnitiumLibrary.Net.Dns;
using static LogExporter.SinkConfig;

namespace LogExporter
{
    public class AppConfig
    {
        [JsonPropertyName("sinks")]
        public SinkConfig Sinks { get; set; }

        [JsonPropertyName("pipeline")]
        public PipelineConfig Pipeline { get; set; }

        /// <summary>
        /// Loads config and enforces DataAnnotations validation.
        ///<para>
        /// ADR: Validation is intentionally centralized here so that:
        ///   - App receives only a fully valid configuration.
        ///   - Errors surface early with domain-specific messages.
        ///   - No runtime failures occur deep inside the logging pipeline.
        /// This ensures plugin initialization is deterministic and safe.
        /// </para>
        /// </summary>
        public static AppConfig Deserialize(string json)
        {
            AppConfig config = JsonSerializer.Deserialize<AppConfig>(json, DnsConfigSerializerOptions.Default)
                         ?? throw new DnsClientException("Configuration could not be deserialized.");

            ValidateObject(config);

            // Validate enabled targets only — disabled ones may be incomplete by design.

            if (config.Sinks.FileSinkConfig?.Enabled is true)
                ValidateObject(config.Sinks.FileSinkConfig);

            if (config.Sinks.HttpSinkConfig?.Enabled is true)
                ValidateObject(config.Sinks.HttpSinkConfig);

            if (config.Sinks.SyslogSinkConfig?.Enabled is true)
                ValidateObject(config.Sinks.SyslogSinkConfig);

            return config;
        }

        private static void ValidateObject(object instance)
        {
            ValidationContext ctx = new ValidationContext(instance);
            Validator.ValidateObject(instance, ctx, validateAllProperties: true);
        }
    }
    public class FeatureBase
    {
        [JsonPropertyName("enabled")]
        public bool Enabled { get; set; } = true;
    }

    public class SinkConfig
    {
        [Range(1, int.MaxValue, ErrorMessage = "maxQueueSize must be greater than zero.")]

        [JsonPropertyName("maxQueueSize")]
        public int MaxQueueSize { get; set; } = int.MaxValue;

        [JsonPropertyName("enableEdnsLogging")]
        public bool EnableEdnsLogging { get; set; } = true;

        [JsonPropertyName("console")]
        public ConsoleSink ConsoleSinkConfig { get; set; }

        [JsonPropertyName("file")]
        public FileSink FileSinkConfig { get; set; }

        [JsonPropertyName("http")]
        public HttpSink HttpSinkConfig { get; set; }

        [JsonPropertyName("syslog")]
        public SyslogSink SyslogSinkConfig { get; set; }

        public class SyslogSink : FeatureBase
        {
            [Required(ErrorMessage = "syslog.address is required when syslog logging is enabled.")]
            [JsonPropertyName("address")]
            public string Address { get; set; }

            [Range(1, 65535)]
            [JsonPropertyName("port")]
            public int? Port { get; set; }

            [AllowedValues(["UDP", "TCP", "TLS", "LOCAL"])]
            [JsonPropertyName("protocol")]
            public string Protocol { get; set; }
        }

        public class ConsoleSink : FeatureBase
        {
        }

        public class FileSink : FeatureBase
        {
            [Required(ErrorMessage = "file.path is required when syslog logging is enabled.")]
            [JsonPropertyName("path")]
            public string Path { get; set; }
        }

        public class HttpSink : FeatureBase
        {

            [Required(ErrorMessage = "http.endpoint is required when HTTP logging is enabled.")]
            [Url]
            [JsonPropertyName("endpoint")]
            public string Endpoint { get; set; }

            [JsonPropertyName("headers")]
            public Dictionary<string, string?>? Headers { get; set; }
        }
    }

    public class PipelineConfig
    {
        [JsonPropertyName("normalize")]
        public NormalizeProcess NormalizeProcessConfig { get; set; }

        public class NormalizeProcess : FeatureBase
        {

        }
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
