namespace DnsServerNew.Auth.Models;

internal class UserLoginResponse : LoginResponse
{
    public string? DisplayName { get; set; }    
    public string? Username { get; set; }    
    public string? Token { get; set; }    
}