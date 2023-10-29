/*
Technitium DNS Server
Copyright (C) 2023  Shreyas Zare (shreyas@technitium.com)

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

using DnsServerCore.Auth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using System;
using System.Net;
using System.Text.Json;
using TechnitiumLibrary.Net;

namespace DnsServerCore
{
    static class Extensions
    {
        readonly static string[] HTTP_METHODS = new string[] { "GET", "POST" };

        public static IPEndPoint GetRemoteEndPoint(this HttpContext context, bool ignoreXRealIpHeader = false)
        {
            try
            {
                IPAddress remoteIP = context.Connection.RemoteIpAddress;
                if (remoteIP is null)
                    return new IPEndPoint(IPAddress.Any, 0);

                if (remoteIP.IsIPv4MappedToIPv6)
                    remoteIP = remoteIP.MapToIPv4();

                if (!ignoreXRealIpHeader && NetUtilities.IsPrivateIP(remoteIP))
                {
                    string xRealIp = context.Request.Headers["X-Real-IP"];
                    if (IPAddress.TryParse(xRealIp, out IPAddress address))
                    {
                        //get the real IP address of the requesting client from X-Real-IP header set in nginx proxy_pass block
                        return new IPEndPoint(address, 0);
                    }
                }

                return new IPEndPoint(remoteIP, context.Connection.RemotePort);
            }
            catch
            {
                return new IPEndPoint(IPAddress.Any, 0);
            }
        }

        public static IPAddress GetLocalIpAddress(this HttpContext context)
        {
            try
            {
                IPAddress localIP = context.Connection.LocalIpAddress;
                if (localIP is null)
                    return IPAddress.Any;

                if (localIP.IsIPv4MappedToIPv6)
                    localIP = localIP.MapToIPv4();

                return localIP;
            }
            catch
            {
                return IPAddress.Any;
            }
        }

        public static UserSession GetCurrentSession(this HttpContext context)
        {
            if (context.Items["session"] is UserSession userSession)
                return userSession;

            throw new InvalidOperationException();
        }

        public static Utf8JsonWriter GetCurrentJsonWriter(this HttpContext context)
        {
            if (context.Items["jsonWriter"] is Utf8JsonWriter jsonWriter)
                return jsonWriter;

            throw new InvalidOperationException();
        }

        public static IEndpointConventionBuilder MapGetAndPost(this IEndpointRouteBuilder endpoints, string pattern, RequestDelegate requestDelegate)
        {
            return endpoints.MapMethods(pattern, HTTP_METHODS, requestDelegate);
        }

        public static IEndpointConventionBuilder MapGetAndPost(this IEndpointRouteBuilder endpoints, string pattern, Delegate handler)
        {
            return endpoints.MapMethods(pattern, HTTP_METHODS, handler);
        }

        public static string QueryOrForm(this HttpRequest request, string parameter)
        {
            string value = request.Query[parameter];
            if ((value is null) && request.HasFormContentType)
                value = request.Form[parameter];

            return value;
        }

        public static string GetQueryOrForm(this HttpRequest request, string parameter)
        {
            string value = request.QueryOrForm(parameter);
            if (string.IsNullOrEmpty(value))
                throw new DnsWebServiceException("Parameter '" + parameter + "' missing.");

            return value;
        }

        public static string GetQueryOrForm(this HttpRequest request, string parameter, string defaultValue)
        {
            string value = request.QueryOrForm(parameter);
            if (string.IsNullOrEmpty(value))
                return defaultValue;

            return value;
        }

        public static T GetQueryOrForm<T>(this HttpRequest request, string parameter, Func<string, T> parse)
        {
            string value = request.QueryOrForm(parameter);
            if (string.IsNullOrEmpty(value))
                throw new DnsWebServiceException("Parameter '" + parameter + "' missing.");

            return parse(value);
        }

        public static T GetQueryOrFormEnum<T>(this HttpRequest request, string parameter) where T : struct
        {
            string value = request.QueryOrForm(parameter);
            if (string.IsNullOrEmpty(value))
                throw new DnsWebServiceException("Parameter '" + parameter + "' missing.");

            return Enum.Parse<T>(value, true);
        }

        public static T GetQueryOrForm<T>(this HttpRequest request, string parameter, Func<string, T> parse, T defaultValue)
        {
            string value = request.QueryOrForm(parameter);
            if (string.IsNullOrEmpty(value))
                return defaultValue;

            return parse(value);
        }

        public static T GetQueryOrFormEnum<T>(this HttpRequest request, string parameter, T defaultValue) where T : struct
        {
            string value = request.QueryOrForm(parameter);
            if (string.IsNullOrEmpty(value))
                return defaultValue;

            return Enum.Parse<T>(value, true);
        }

        public static bool TryGetQueryOrForm(this HttpRequest request, string parameter, out string value)
        {
            value = request.QueryOrForm(parameter);
            if (string.IsNullOrEmpty(value))
                return false;

            return true;
        }

        public static bool TryGetQueryOrForm<T>(this HttpRequest request, string parameter, Func<string, T> parse, out T value)
        {
            string strValue = request.QueryOrForm(parameter);
            if (string.IsNullOrEmpty(strValue))
            {
                value = default;
                return false;
            }

            value = parse(strValue);
            return true;
        }

        public static bool TryGetQueryOrFormEnum<T>(this HttpRequest request, string parameter, out T value) where T : struct
        {
            string strValue = request.QueryOrForm(parameter);
            if (string.IsNullOrEmpty(strValue))
            {
                value = default;
                return false;
            }

            return Enum.TryParse(strValue, true, out value);
        }

        public static string GetQueryOrFormAlt(this HttpRequest request, string parameter, string alternateParameter)
        {
            string value = request.QueryOrForm(parameter);
            if (string.IsNullOrEmpty(value))
            {
                value = request.QueryOrForm(alternateParameter);
                if (string.IsNullOrEmpty(value))
                    throw new DnsWebServiceException("Parameter '" + parameter + "' missing.");
            }

            return value;
        }

        public static string GetQueryOrFormAlt(this HttpRequest request, string parameter, string alternateParameter, string defaultValue)
        {
            string value = request.QueryOrForm(parameter);
            if (string.IsNullOrEmpty(value))
            {
                value = request.QueryOrForm(alternateParameter);
                if (string.IsNullOrEmpty(value))
                    return defaultValue;
            }

            return value;
        }

        public static T GetQueryOrFormAlt<T>(this HttpRequest request, string parameter, string alternateParameter, Func<string, T> parse)
        {
            string value = request.QueryOrForm(parameter);
            if (string.IsNullOrEmpty(value))
            {
                value = request.QueryOrForm(alternateParameter);
                if (string.IsNullOrEmpty(value))
                    throw new DnsWebServiceException("Parameter '" + parameter + "' missing.");
            }

            return parse(value);
        }

        public static T GetQueryOrFormAlt<T>(this HttpRequest request, string parameter, string alternateParameter, Func<string, T> parse, T defaultValue)
        {
            string value = request.QueryOrForm(parameter);
            if (string.IsNullOrEmpty(value))
            {
                value = request.QueryOrForm(alternateParameter);
                if (string.IsNullOrEmpty(value))
                    return defaultValue;
            }

            return parse(value);
        }
    }
}
