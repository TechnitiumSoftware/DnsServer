$(function () {
    var hostname = window.location.hostname;

    var dohLink = "https://" + hostname + "/dns-query";
    var dotLink = hostname;

    // Assign to copy buttons
    $("button.copyBtn[data-type='doh']").data("ip", dohLink);
    $("button.copyBtn[data-type='dot']").data("ip", dotLink);

    // DoH
    $(".lnkDoH").text(dohLink).attr("href", dohLink);
    $(".lnkDoHText").text(dohLink);

    // DoT
    $(".lnkDoT").text(dotLink).attr("href", "tls://" + dotLink);
    $(".lnkDoTText").text(dotLink);

    // Update DNS IPs
    function updateDNSLinks(recordType, selector, textSelector, dataAttr) {
        $.ajax({
            url: "https://cloudflare-dns.com/dns-query",
            data: {
                name: hostname,
                type: recordType
            },
            headers: {
                "Accept": "application/dns-json"
            },
            success: function (data) {
                if (data && data.Answer && data.Answer.length > 0) {
                    var ip = null;
                    for (var i = 0; i < data.Answer.length; i++) {
                        if ((recordType === "A" && data.Answer[i].type === 1) ||
                            (recordType === "AAAA" && data.Answer[i].type === 28)) {
                            ip = data.Answer[i].data;
                            break;
                        }
                    }

                    if (ip) {
                        $(selector).text(ip).attr("href", "dns://" + ip);
                        $(textSelector).text(ip);

                        $("button.copyBtn[data-type='" + dataAttr + "']").data("ip", ip);
                    }
                }
            },
            error: function () {
                $(selector).text("IP resolution failed").attr("href", "#");
                $(textSelector).text("IP resolution failed");
            }
        });
    }

    updateDNSLinks("A", ".lnkDNSv4", ".lnkDNSv4Text", "v4");
    updateDNSLinks("AAAA", ".lnkDNSv6", ".lnkDNSv6Text", "v6");

    // Copy buttons
    $(document).on("click", "button.copyBtn", function () {
        var ip = $(this).data("ip");
        if (ip) {
            navigator.clipboard.writeText(ip).then(function () {
                $('<div class="alert alert-success copy-alert" style="position: fixed; top: 20px; right: 20px; z-index: 9999;">Copied: ' + ip + '</div>')
                    .appendTo('body')
                    .delay(1500)
                    .fadeOut(500, function () { $(this).remove(); });
            }, function () {
                alert("Copy failed");
            });
        }
    });

    // Mobileconfig for iOS
    $("#downloadProfile").on("click", function () {
        var dotHostname = dotLink;
        if (dotHostname) {
            generateMobileConfig(dotHostname);
        } else {
            alert("DoT hostname not ready yet. Please wait!");
        }
    });

    function generateMobileConfig(dotHostname) {
        var configContent = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>TLS</string>
                <key>ServerAddresses</key>
                <array/>
                <key>ServerName</key>
                <string>${dotHostname}</string>
            </dict>
            <key>PayloadDescription</key>
            <string>Configures ${dotHostname} DoT DNS server for iOS</string>
            <key>PayloadDisplayName</key>
            <string>${dotHostname} DNS Settings</string>
            <key>PayloadIdentifier</key>
            <string>com.${dotHostname}.dnssettings</string>
            <key>PayloadOrganization</key>
            <string>${dotHostname}</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>EB6E1234-1234-5678-ABCD-9876DCBA4321</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>${dotHostname} DNS iOS</string>
    <key>PayloadIdentifier</key>
    <string>com.${dotHostname}.dnsprofile</string>
    <key>PayloadOrganization</key>
    <string>${dotHostname}</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>7F6B5678-90AB-4321-CDEF-1234567890AB</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>`;

        var blob = new Blob([configContent], { type: "application/x-apple-aspen-config" });
        var url = URL.createObjectURL(blob);

        var safeFilename = dotHostname.replace(/[^a-zA-Z0-9.-]/g, "_");
        var finalFilename = safeFilename + ".mobileconfig";

        var a = document.createElement("a");
        a.href = url;
        a.download = finalFilename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // Mobileconfig for macOS
    $("#downloadMacProfile").on("click", function () {
        var dotHostname = dotLink;
        if (dotHostname) {
            generateMacConfig(dotHostname);
        } else {
            alert("DoT hostname not ready yet. Please wait!");
        }
    });

    function generateMacConfig(dotHostname) {
        var configContent = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>TLS</string>
                <key>ServerAddresses</key>
                <array/>
                <key>ServerName</key>
                <string>${dotHostname}</string>
            </dict>
            <key>PayloadDescription</key>
            <string>Configures ${dotHostname} DoT DNS server for macOS</string>
            <key>PayloadDisplayName</key>
            <string>${dotHostname} DNS Settings</string>
            <key>PayloadIdentifier</key>
            <string>com.${dotHostname}.dnssettings.macos</string>
            <key>PayloadOrganization</key>
            <string>${dotHostname}</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>EB6E1234-1234-5678-ABCD-9876DCBA9999</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>${dotHostname} DNS macOS</string>
    <key>PayloadIdentifier</key>
    <string>com.${dotHostname}.dnsprofile.macos</string>
    <key>PayloadOrganization</key>
    <string>${dotHostname}</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>7F6B5678-90AB-4321-CDEF-1234567890CD</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>`;

        var blob = new Blob([configContent], { type: "application/x-apple-aspen-config" });
        var url = URL.createObjectURL(blob);

        var safeFilename = dotHostname.replace(/[^a-zA-Z0-9.-]/g, "_");
        var finalFilename = safeFilename + "_macOS.mobileconfig";

        var a = document.createElement("a");
        a.href = url;
        a.download = finalFilename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

   
});
