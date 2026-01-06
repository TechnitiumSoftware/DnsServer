using System;
using System.Text.Json.Serialization;

namespace ProxmoxAutodiscovery;

public sealed class AppConfiguration
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }
    
    [JsonPropertyName("proxmoxHost")]
    public Uri ProxmoxHost { get; set; }
    
    [JsonPropertyName("timeoutSeconds")]
    public int TimeoutSeconds { get; set; } = 15;
    
    [JsonPropertyName("disableSslValidation")]
    public bool DisableSslValidation { get; set; }
    
    [JsonPropertyName("accessToken")]
    public string AccessToken { get; set; }
    
    [JsonPropertyName("periodSeconds")]
    public int PeriodSeconds { get; set; } = 60;
}
