using System;
using System.Net;
using System.Reflection;
using System.Text.Json;
using Failover;
using DnsServerCore.ApplicationCommon;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

MethodInfo? parse = typeof(Address).GetMethod("GetEnabledAddress", BindingFlags.NonPublic | BindingFlags.Static);
if (parse is null)
    throw new Exception("The Failover handler must support enabled/disabled backend entries.");

foreach ((string json, string? expected) in new (string, string?)[]
{
    ("\"192.0.2.1\"", "192.0.2.1"),
    ("\"2001:db8::1\"", "2001:db8::1"),
    ("{\"address\":\"192.0.2.1\"}", "192.0.2.1"),
    ("{\"address\":\"2001:db8::1\",\"enabled\":true}", "2001:db8::1"),
    ("{\"address\":\"192.0.2.1\",\"enabled\":false}", null),
    ("{\"address\":\"2001:db8::1\",\"enabled\":false}", null),
    ("null", null),
    ("123", null)
})
{
    using JsonDocument document = JsonDocument.Parse(json);
    IPAddress? actual = (IPAddress?)parse.Invoke(null, [document.RootElement]);
    if (actual?.ToString() != expected)
        throw new Exception($"Unexpected enabled address for {json}: {actual}");
}

foreach (string json in new[] { "\"invalid\"", "{\"address\":\"invalid\"}", "{\"address\":\"192.0.2.1\",\"enabled\":\"false\"}" })
{
    using JsonDocument document = JsonDocument.Parse(json);
    try
    {
        parse.Invoke(null, [document.RootElement]);
    }
    catch (TargetInvocationException)
    {
        continue;
    }
    throw new Exception($"Invalid backend data was accepted: {json}");
}

using Address app = new Address();
await app.InitializeAsync(DispatchProxy.Create<IDnsServer, NoNetworkDnsServer>(), """
    {"healthChecks":[],"emailAlerts":[],"webHooks":[]}
    """);
if (!((IDnsAppRecordEditor)app).ApplicationRecordDataEditor!.Contains("dns-app-record-editor:init"))
    throw new Exception("The app-owned editor must be embedded in the app assembly.");

foreach (DnsResourceRecordType type in new[] { DnsResourceRecordType.A, DnsResourceRecordType.AAAA })
{
    string address = type == DnsResourceRecordType.A ? "192.0.2.1" : "2001:db8::1";
    string otherAddress = type == DnsResourceRecordType.A ? "192.0.2.2" : "2001:db8::2";
    string disabled = "{\"address\":\"not-an-ip\",\"enabled\":false}";
    string data = $$"""
        {"primary":[{{disabled}}],"secondary":[{{disabled}}],
         "serverDown":[{{disabled}},"{{address}}",{"address":"{{otherAddress}}","enabled":true}],
         "healthCheck":"not-configured"}
        """;
    DnsDatagram? response = await Query(type, data);
    if (response?.Answer.Count != 2)
        throw new Exception($"{type}: disabled primary/secondary must fall back to enabled serverDown entries.");
    foreach (DnsResourceRecord answer in response.Answer)
    {
        IPAddress actual = answer.RDATA is DnsARecordData a ? a.Address : ((DnsAAAARecordData)answer.RDATA).Address;
        if (actual.ToString() != address && actual.ToString() != otherAddress)
            throw new Exception($"Disabled address was returned: {actual}");
    }
    if (await Query(type, $$"""{"primary":[{{disabled}}],"secondary":[{{disabled}}],"serverDown":[{{disabled}}],"healthCheck":"not-configured"}""") is not null)
        throw new Exception($"{type}: all-disabled records must not answer.");
}

DnsDatagram? status = await Query(DnsResourceRecordType.TXT, """
    {"primary":[{"address":"192.0.2.1","enabled":false},"192.0.2.2"],
     "secondary":[{"address":"2001:db8::1","enabled":false},"2001:db8::2"],
     "healthCheck":"not-configured","allowTxtStatus":true}
    """);
if (status?.Answer.Count != 2)
    throw new Exception("TXT status must exclude disabled IPv4 and IPv6 addresses.");

Console.WriteLine("Failover parsing, embedded editor, IPv4/IPv6 fallback, all-disabled, and TXT status checks passed.");

async System.Threading.Tasks.Task<DnsDatagram?> Query(DnsResourceRecordType type, string data)
{
    DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false,
        DnsResponseCode.NoError, [new DnsQuestionRecord("www.example.com", type, DnsClass.IN)]);
    return await app.ProcessRequestAsync(request, new IPEndPoint(IPAddress.Loopback, 0), DnsTransportProtocol.Udp,
        false, "example.com", "www.example.com", 300, data);
}

public class NoNetworkDnsServer : DispatchProxy
{
    protected override object? Invoke(MethodInfo? method, object?[]? args)
    {
        if (method?.Name == "WriteLog")
            return null;
        throw new Exception("Unexpected DNS server access during the test: " + method?.Name);
    }
}
