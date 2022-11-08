using System.Net;
using Microsoft.AspNetCore.Http;
using TechnitiumLibrary.Net;

namespace DnsServerNew.Extensions;

public static class RequestExtensions
{
    internal static IPEndPoint GetRemoteEndPoint(this HttpRequest request)
    {
        try
        {
            var connection = request.HttpContext.Connection;
            if (connection.RemoteIpAddress == null)
                return new IPEndPoint(IPAddress.Any, 0);

            if (NetUtilities.IsPrivateIP(connection.RemoteIpAddress))
            {
                string xRealIp = request.Headers["X-Real-IP"];
                if (IPAddress.TryParse(xRealIp, out var address))
                {
                    //get the real IP address of the requesting client from X-Real-IP header set in nginx proxy_pass block
                    return new IPEndPoint(address, 0);
                }
            }

            return new IPEndPoint(connection.RemoteIpAddress, connection.RemotePort);
        }
        catch
        {
            return new IPEndPoint(IPAddress.Any, 0);
        }
    }
}