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
using System.Text.Json.Serialization;

namespace TyposquattingDetector
{
    public sealed partial class App
    {
        private class Config
        {
            [JsonPropertyName("enable")]
            public bool Enable { get; set; } = true;

            [JsonPropertyName("url")]
            [Required(ErrorMessage = "url is a required configuration property.")]
            [Url(ErrorMessage = "url must be a valid URL.")]
            public string Url { get; set; }

            [JsonPropertyName("disableTlsValidation")]
            public bool DisableTlsValidation { get; set; } = false;

            [JsonPropertyName("updateInterval")]
            [Required(ErrorMessage = "updateInterval is a required configuration property.")]
            [RegularExpression(@"^\d+[mhd]$", ErrorMessage = "Invalid interval format. Use a number followed by 'm', 'h', or 'd' (e.g., '90m', '2h', '7d').", MatchTimeoutInMilliseconds = 3000)]
            public string UpdateInterval { get; set; }

            [JsonPropertyName("allowTxtBlockingReport")]
            public bool AllowTxtBlockingReport { get; set; } = true;


            [JsonPropertyName("addExtendedDnsError")]
            public bool AddExtendedDnsError { get; set; } = true;
            
            [JsonPropertyName("fuzzyMatchThreshold")]
            [Range(75, 90, ErrorMessage = "fuzzyMatchThreshold must be between 75 and 90.")]
            [Required(ErrorMessage = "fuzzyMatchThreshold is a required configuration property. The lower threshold means more false positives.")]
            public int FuzzyMatchThreshold { get; set; } = 75;
        }
    }
}