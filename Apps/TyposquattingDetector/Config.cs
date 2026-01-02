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

using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace TyposquattingDetector
{
    public sealed partial class App
    {
        private class Config
        {
            [JsonPropertyName("addExtendedDnsError")]
            public bool AddExtendedDnsError { get; set; } = true;

            [JsonPropertyName("allowTxtBlockingReport")]
            public bool AllowTxtBlockingReport { get; set; } = true;

            [JsonPropertyName("disableTlsValidation")]
            public bool DisableTlsValidation { get; set; } = false;

            [JsonPropertyName("enable")]
            public bool Enable { get; set; } = true;

            [JsonPropertyName("fuzzyMatchThreshold")]
            [Range(75, 90, ErrorMessage = "fuzzyMatchThreshold must be between 75 and 90.")]
            [Required(ErrorMessage = "fuzzyMatchThreshold is a required configuration property. The lower threshold means more false positives.")]
            public int FuzzyMatchThreshold { get; set; } = 75;

            [JsonPropertyName("customList")]
            [CustomValidation(typeof(FileContentValidator), nameof(FileContentValidator.ValidateDomainFile))]
            public string? Path { get; set; }

            [JsonPropertyName("updateInterval")]
            [Required(ErrorMessage = "updateInterval is a required configuration property.")]
            [RegularExpression(@"^\d+[mhdw]$", ErrorMessage = "Invalid interval format. Use a number followed by 'm', 'h', or 'd' (e.g., '90m', '2h', '7d').", MatchTimeoutInMilliseconds = 3000)]
            public string UpdateInterval { get; set; } = "30d";
        }

        public partial class FileContentValidator
        {
            // Optimized Regex: Compiled for performance during "Happy Path" scans
            private static readonly Regex DomainRegex = DomainPattern();

            public static ValidationResult? ValidateDomainFile(string? path, ValidationContext context)
            {
                // 1. If path is null/empty, we assume validation is not required here
                // (Use [Required] on the property if you want to force a path to be provided)
                if (string.IsNullOrWhiteSpace(path)) return ValidationResult.Success;

                // 2. Existence Check
                if (!File.Exists(path))
                    return new ValidationResult($"File not found: {path}");

                try
                {
                    // 3. Stream through lines
                    // If the file is empty, this loop is simply skipped
                    foreach (string line in File.ReadLines(path))
                    {
                        string trimmedLine = line.Trim();

                        // Skip truly empty lines (whitespace only)
                        if (string.IsNullOrEmpty(trimmedLine)) continue;

                        // 4. Fail-Fast Logic
                        // If any content exists, it MUST follow the domain rules
                        if (trimmedLine.Contains('*') || !DomainRegex.IsMatch(trimmedLine))
                        {
                            return new ValidationResult($"Invalid content: '{trimmedLine}'. Wildcards are not allowed.");
                        }
                    }
                }
                catch (IOException ex)
                {
                    return new ValidationResult($"File access error: {ex.Message}");
                }

                // 5. Success Path
                // Reached if the file was empty OR all lines passed validation
                return ValidationResult.Success;
            }

            [GeneratedRegex(@"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]", RegexOptions.IgnoreCase | RegexOptions.Compiled, "en-US")]
            private static partial Regex DomainPattern();
        }
    }
}