/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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

var refreshTimerHandle;
var reverseProxyDetected = false;

function showPageLogin() {
    hideAlert();

    localStorage.removeItem("token");

    $("#pageMain").hide();
    $("#mnuUser").hide();

    $("#txtUser").val("");
    $("#txtPass").val("");
    $("#btnLogin").button('reset');
    $("#pageLogin").show();

    $("#txtUser").focus();

    if (refreshTimerHandle != null) {
        clearInterval(refreshTimerHandle);
        refreshTimerHandle = null;
    }
}

function showPageMain() {
    hideAlert();

    $("#pageLogin").hide();
    $("#mnuUser").show();

    $(".nav-tabs li").removeClass("active");
    $(".tab-pane").removeClass("active");
    $("#mainPanelTabListDashboard").addClass("active");
    $("#mainPanelTabPaneDashboard").addClass("active");
    $("#settingsTabListGeneral").addClass("active");
    $("#settingsTabPaneGeneral").addClass("active");
    $("#dhcpTabListLeases").addClass("active");
    $("#dhcpTabPaneLeases").addClass("active");
    $("#adminTabListSessions").addClass("active");
    $("#adminTabPaneSessions").addClass("active");
    $("#logsTabListLogViewer").addClass("active");
    $("#logsTabPaneLogViewer").addClass("active");

    $("#divViewZones").show();
    $("#divEditZone").hide();

    $("#divDhcpViewScopes").show();
    $("#divDhcpEditScope").hide();

    $("#txtDnsClientNameServer").val("This Server {this-server}");
    $("#txtDnsClientDomain").val("");
    $("#optDnsClientType").val("A");
    $("#optDnsClientProtocol").val("UDP");
    $("#txtDnsClientEDnsClientSubnet").val("");
    $("#chkDnsClientDnssecValidation").prop("checked", false);
    $("#divDnsClientLoader").hide();
    $("#preDnsClientFinalResponse").text("");
    $("#divDnsClientOutputAccordion").hide();

    $("#divLogViewer").hide();
    $("#divQueryLogsTable").hide();

    if (sessionData.info.permissions.Dashboard.canView) {
        $("#mainPanelTabListDashboard").show();
        refreshDashboard();
    }
    else {
        $("#mainPanelTabListDashboard").hide();

        $("#mainPanelTabListDashboard").removeClass("active");
        $("#mainPanelTabPaneDashboard").removeClass("active");

        if (sessionData.info.permissions.Zones.canView) {
            $("#mainPanelTabListZones").addClass("active");
            $("#mainPanelTabPaneZones").addClass("active");
            refreshZones(true);
        }
        else if (sessionData.info.permissions.Cache.canView) {
            $("#mainPanelTabListCachedZones").addClass("active");
            $("#mainPanelTabPaneCachedZones").addClass("active");
        }
        else if (sessionData.info.permissions.Allowed.canView) {
            $("#mainPanelTabListAllowedZones").addClass("active");
            $("#mainPanelTabPaneAllowedZones").addClass("active");
        }
        else if (sessionData.info.permissions.Blocked.canView) {
            $("#mainPanelTabListBlockedZones").addClass("active");
            $("#mainPanelTabPaneBlockedZones").addClass("active");
        }
        else if (sessionData.info.permissions.Apps.canView) {
            $("#mainPanelTabListApps").addClass("active");
            $("#mainPanelTabPaneApps").addClass("active");
            refreshApps();
        }
        else if (sessionData.info.permissions.DnsClient.canView) {
            $("#mainPanelTabListDnsClient").addClass("active");
            $("#mainPanelTabPaneDnsClient").addClass("active");
        }
        else if (sessionData.info.permissions.Settings.canView) {
            $("#mainPanelTabListSettings").addClass("active");
            $("#mainPanelTabPaneSettings").addClass("active");
            refreshDnsSettings()
        }
        else if (sessionData.info.permissions.DhcpServer.canView) {
            $("#mainPanelTabListDhcp").addClass("active");
            $("#mainPanelTabPaneDhcp").addClass("active");
            refreshDhcpTab();
        }
        else if (sessionData.info.permissions.Administration.canView) {
            $("#mainPanelTabListAdmin").addClass("active");
            $("#mainPanelTabPaneAdmin").addClass("active");
            refreshAdminTab();
        }
        else if (sessionData.info.permissions.Logs.canView) {
            $("#mainPanelTabListLogs").addClass("active");
            $("#mainPanelTabPaneLogs").addClass("active");
            refreshLogsTab();
        }
        else {
            $("#mainPanelTabListAbout").addClass("active");
            $("#mainPanelTabPaneAbout").addClass("active");
        }
    }

    if (sessionData.info.permissions.Zones.canView) {
        $("#mainPanelTabListZones").show();
    }
    else {
        $("#mainPanelTabListZones").hide();
    }

    if (sessionData.info.permissions.Cache.canView) {
        $("#mainPanelTabListCachedZones").show();
        refreshCachedZonesList();
    }
    else {
        $("#mainPanelTabListCachedZones").hide();
    }

    if (sessionData.info.permissions.Allowed.canView) {
        $("#mainPanelTabListAllowedZones").show();
        refreshAllowedZonesList();
    }
    else {
        $("#mainPanelTabListAllowedZones").hide();
    }

    if (sessionData.info.permissions.Blocked.canView) {
        $("#mainPanelTabListBlockedZones").show();
        refreshBlockedZonesList();
    }
    else {
        $("#mainPanelTabListBlockedZones").hide();
    }

    if (sessionData.info.permissions.Apps.canView) {
        $("#mainPanelTabListApps").show();
    }
    else {
        $("#mainPanelTabListApps").hide();
    }

    if (sessionData.info.permissions.DnsClient.canView) {
        $("#mainPanelTabListDnsClient").show();
    }
    else {
        $("#mainPanelTabListDnsClient").hide();
    }

    if (sessionData.info.permissions.Settings.canView) {
        $("#mainPanelTabListSettings").show();
    }
    else {
        $("#mainPanelTabListSettings").hide();
    }

    if (sessionData.info.permissions.DhcpServer.canView) {
        $("#mainPanelTabListDhcp").show();
    }
    else {
        $("#mainPanelTabListDhcp").hide();
    }

    if (sessionData.info.permissions.Administration.canView) {
        $("#mainPanelTabListAdmin").show();
    }
    else {
        $("#mainPanelTabListAdmin").hide();
    }

    if (sessionData.info.permissions.Logs.canView) {
        $("#mainPanelTabListLogs").show();
    }
    else {
        $("#mainPanelTabListLogs").hide();
    }

    $("#pageMain").show();

    checkForUpdate();

    refreshTimerHandle = setInterval(function () {
        var type = $('input[name=rdStatType]:checked').val();
        if (type === "lastHour")
            refreshDashboard(true);

        $("#lblAboutUptime").text(moment(sessionData.info.uptimestamp).local().format("lll") + " (" + moment(sessionData.info.uptimestamp).fromNow() + ")");
    }, 60000);
}

$(function () {
    var headerHtml = $("#header").html();

    $("#header").html("<div class=\"title\"><a href=\"/\"><img src=\"/img/logo25x25.png\" alt=\"Technitium Logo\" /><span class=\"text\" style=\"color: #ffffff;\">Technitium</span></a>" + headerHtml + "</div>");
    $("#footer").html("<div class=\"content\"><a href=\"https://technitium.com/\" target=\"_blank\">Technitium</a> | <a href=\"https://blog.technitium.com/\" target=\"_blank\">Blog</a> | <a href=\"https://go.technitium.com/?id=35\" target=\"_blank\">Donate</a> | <a href=\"https://dnsclient.net/\" target=\"_blank\">DNS Client</a> | <a href=\"https://github.com/TechnitiumSoftware/DnsServer\" target=\"_blank\"><i class=\"fa fa-github\"></i>&nbsp;GitHub</a> | <a href=\"#\" onclick=\"showAbout(); return false;\">About</a></div>");

    //dropdown list box support
    $('.dropdown').on('click', 'a', function (e) {
        e.preventDefault();

        var itemText = $(this).text();
        $(this).closest('.dropdown').find('input').val(itemText);

        if (itemText.indexOf("QUIC") !== -1)
            $("#optDnsClientProtocol").val("QUIC");
        else if ((itemText.indexOf("TLS") !== -1) || (itemText.indexOf(":853") !== -1))
            $("#optDnsClientProtocol").val("TLS");
        else if ((itemText.indexOf("HTTPS") !== -1) || (itemText.indexOf("http://") !== -1) || (itemText.indexOf("https://") !== -1))
            $("#optDnsClientProtocol").val("HTTPS");
        else {
            switch ($("#optDnsClientProtocol").val()) {
                case "UDP":
                case "TCP":
                    break;

                default:
                    $("#optDnsClientProtocol").val("UDP");
                    break;
            }
        }
    });

    $("#chkEDnsClientSubnet").click(function () {
        var eDnsClientSubnet = $("#chkEDnsClientSubnet").prop("checked");

        $("#txtEDnsClientSubnetIPv4PrefixLength").prop("disabled", !eDnsClientSubnet);
        $("#txtEDnsClientSubnetIPv6PrefixLength").prop("disabled", !eDnsClientSubnet);
        $("#txtEDnsClientSubnetIpv4Override").prop("disabled", !eDnsClientSubnet);
        $("#txtEDnsClientSubnetIpv6Override").prop("disabled", !eDnsClientSubnet);
    });

    $("#chkEnableBlocking").click(updateBlockingState);

    $("input[type=radio][name=rdProxyType]").change(function () {
        var proxyType = $('input[name=rdProxyType]:checked').val().toLowerCase();
        if (proxyType === "none") {
            $("#txtProxyAddress").prop("disabled", true);
            $("#txtProxyPort").prop("disabled", true);
            $("#txtProxyUsername").prop("disabled", true);
            $("#txtProxyPassword").prop("disabled", true);
            $("#txtProxyBypassList").prop("disabled", true);
        }
        else {
            $("#txtProxyAddress").prop("disabled", false);
            $("#txtProxyPort").prop("disabled", false);
            $("#txtProxyUsername").prop("disabled", false);
            $("#txtProxyPassword").prop("disabled", false);
            $("#txtProxyBypassList").prop("disabled", false);
        }
    });

    $("input[type=radio][name=rdRecursion]").change(function () {
        var recursion = $('input[name=rdRecursion]:checked').val();

        $("#txtRecursionNetworkACL").prop("disabled", recursion !== "UseSpecifiedNetworkACL");
    });

    $("input[type=radio][name=rdBlockingType]").change(function () {
        var recursion = $('input[name=rdBlockingType]:checked').val();
        if (recursion === "CustomAddress") {
            $("#txtCustomBlockingAddresses").prop("disabled", false);
        }
        else {
            $("#txtCustomBlockingAddresses").prop("disabled", true);
        }
    });

    $("#chkWebServiceEnableTls").click(function () {
        var webServiceEnableTls = $("#chkWebServiceEnableTls").prop("checked");
        $("#chkWebServiceEnableHttp3").prop("disabled", !webServiceEnableTls);
        $("#chkWebServiceHttpToTlsRedirect").prop("disabled", !webServiceEnableTls);
        $("#chkWebServiceUseSelfSignedTlsCertificate").prop("disabled", !webServiceEnableTls);
        $("#txtWebServiceTlsPort").prop("disabled", !webServiceEnableTls);
        $("#txtWebServiceTlsCertificatePath").prop("disabled", !webServiceEnableTls);
        $("#txtWebServiceTlsCertificatePassword").prop("disabled", !webServiceEnableTls);
    });

    $("#chkEnableDnsOverUdpProxy").click(function () {
        var enableDnsOverUdpProxy = $("#chkEnableDnsOverUdpProxy").prop("checked");
        var enableDnsOverTcpProxy = $("#chkEnableDnsOverTcpProxy").prop("checked");
        var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");

        $("#txtDnsOverUdpProxyPort").prop("disabled", !enableDnsOverUdpProxy);
        $("#txtReverseProxyNetworkACL").prop("disabled", !enableDnsOverUdpProxy && !enableDnsOverTcpProxy && !enableDnsOverHttp && !enableDnsOverHttps);
    });

    $("#chkEnableDnsOverTcpProxy").click(function () {
        var enableDnsOverUdpProxy = $("#chkEnableDnsOverUdpProxy").prop("checked");
        var enableDnsOverTcpProxy = $("#chkEnableDnsOverTcpProxy").prop("checked");
        var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");

        $("#txtDnsOverTcpProxyPort").prop("disabled", !enableDnsOverTcpProxy);
        $("#txtReverseProxyNetworkACL").prop("disabled", !enableDnsOverUdpProxy && !enableDnsOverTcpProxy && !enableDnsOverHttp && !enableDnsOverHttps);
    });

    $("#chkEnableDnsOverHttp").click(function () {
        var enableDnsOverUdpProxy = $("#chkEnableDnsOverUdpProxy").prop("checked");
        var enableDnsOverTcpProxy = $("#chkEnableDnsOverTcpProxy").prop("checked");
        var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");

        $("#txtDnsOverHttpPort").prop("disabled", !enableDnsOverHttp);
        $("#txtReverseProxyNetworkACL").prop("disabled", !enableDnsOverUdpProxy && !enableDnsOverTcpProxy && !enableDnsOverHttp && !enableDnsOverHttps);
        $("#txtDnsOverHttpRealIpHeader").prop("disabled", !enableDnsOverHttp && !enableDnsOverHttps);
    });

    $("#chkEnableDnsOverTls").click(function () {
        var enableDnsOverTls = $("#chkEnableDnsOverTls").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");
        var enableDnsOverQuic = $("#chkEnableDnsOverQuic").prop("checked");

        $("#txtDnsOverTlsPort").prop("disabled", !enableDnsOverTls);
        $("#txtDnsTlsCertificatePath").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic);
        $("#txtDnsTlsCertificatePassword").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic);
    });

    $("#chkEnableDnsOverHttps").click(function () {
        var enableDnsOverUdpProxy = $("#chkEnableDnsOverUdpProxy").prop("checked");
        var enableDnsOverTcpProxy = $("#chkEnableDnsOverTcpProxy").prop("checked");
        var enableDnsOverTls = $("#chkEnableDnsOverTls").prop("checked");
        var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");
        var enableDnsOverQuic = $("#chkEnableDnsOverQuic").prop("checked");

        $("#chkEnableDnsOverHttp3").prop("disabled", !enableDnsOverHttps);
        $("#txtDnsOverHttpsPort").prop("disabled", !enableDnsOverHttps);
        $("#txtReverseProxyNetworkACL").prop("disabled", !enableDnsOverUdpProxy && !enableDnsOverTcpProxy && !enableDnsOverHttp && !enableDnsOverHttps);
        $("#txtDnsTlsCertificatePath").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic);
        $("#txtDnsTlsCertificatePassword").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic);
        $("#txtDnsOverHttpRealIpHeader").prop("disabled", !enableDnsOverHttp && !enableDnsOverHttps);
    });

    $("#chkEnableDnsOverQuic").click(function () {
        var enableDnsOverTls = $("#chkEnableDnsOverTls").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");
        var enableDnsOverQuic = $("#chkEnableDnsOverQuic").prop("checked");

        $("#txtDnsOverQuicPort").prop("disabled", !enableDnsOverQuic);
        $("#txtDnsTlsCertificatePath").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic);
        $("#txtDnsTlsCertificatePassword").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic);
    });

    $("#chkEnableConcurrentForwarding").click(function () {
        var concurrentForwarding = $("#chkEnableConcurrentForwarding").prop("checked");
        $("#txtForwarderConcurrency").prop("disabled", !concurrentForwarding)
    });

    $("#chkEnableLogging").click(function () {
        var enableLogging = $("#chkEnableLogging").prop("checked");
        $("#chkIgnoreResolverLogs").prop("disabled", !enableLogging);
        $("#chkLogQueries").prop("disabled", !enableLogging);
        $("#chkUseLocalTime").prop("disabled", !enableLogging);
        $("#txtLogFolderPath").prop("disabled", !enableLogging);
    });

    $("#chkServeStale").click(function () {
        var serveStale = $("#chkServeStale").prop("checked");
        $("#txtServeStaleTtl").prop("disabled", !serveStale);
    });

    $("#optQuickBlockList").change(function () {

        var selectedOption = $("#optQuickBlockList").val();

        switch (selectedOption) {
            case "blank":
                break;

            case "none":
                $("#txtBlockListUrls").val("");
                break;

            case "default":
                var defaultList = "";

                defaultList += "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts\n";

                $("#txtBlockListUrls").val(defaultList);
                break;

            default:
                var existingList = $("#txtBlockListUrls").val();

                if (existingList.indexOf(selectedOption) < 0) {
                    existingList += selectedOption + "\n";
                    $("#txtBlockListUrls").val(existingList);
                }

                break;
        }
    });

    $("#optQuickForwarders").change(function () {

        var selectedOption = $("#optQuickForwarders").val();

        if (selectedOption !== "blank") {
            if (($('input[name=rdProxyType]:checked').val() === "Socks5") && ($("#txtProxyAddress").val() === "127.0.0.1") && ($("#txtProxyPort").val() === "9150")) {
                $("#rdProxyTypeNone").prop("checked", true);
                $("#txtProxyAddress").prop("disabled", true);
                $("#txtProxyPort").prop("disabled", true);
                $("#txtProxyUsername").prop("disabled", true);
                $("#txtProxyPassword").prop("disabled", true);
                $("#txtProxyAddress").val("");
                $("#txtProxyPort").val("");
                $("#txtProxyUsername").val("");
                $("#txtProxyPassword").val("");
            }
        }

        switch (selectedOption) {
            case "cloudflare-udp":
                $("#txtForwarders").val("1.1.1.1\r\n1.0.0.1");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;

            case "cloudflare-udp-ipv6":
                $("#txtForwarders").val("[2606:4700:4700::1111]\r\n[2606:4700:4700::1001]");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;

            case "cloudflare-tcp":
                $("#txtForwarders").val("1.1.1.1\r\n1.0.0.1");
                $("#rdForwarderProtocolTcp").prop("checked", true);
                break;

            case "cloudflare-tcp-ipv6":
                $("#txtForwarders").val("[2606:4700:4700::1111]\r\n[2606:4700:4700::1001]");
                $("#rdForwarderProtocolTcp").prop("checked", true);
                break;

            case "cloudflare-tls":
                $("#txtForwarders").val("cloudflare-dns.com (1.1.1.1:853)\r\ncloudflare-dns.com (1.0.0.1:853)");
                $("#rdForwarderProtocolTls").prop("checked", true);
                break;

            case "cloudflare-tls-ipv6":
                $("#txtForwarders").val("cloudflare-dns.com ([2606:4700:4700::1111]:853)\r\ncloudflare-dns.com ([2606:4700:4700::1001]:853)");
                $("#rdForwarderProtocolTls").prop("checked", true);
                break;

            case "cloudflare-https":
                $("#txtForwarders").val("https://cloudflare-dns.com/dns-query (1.1.1.1)\r\nhttps://cloudflare-dns.com/dns-query (1.0.0.1)");
                $("#rdForwarderProtocolHttps").prop("checked", true);
                break;

            case "cloudflare-https-ipv6":
                $("#txtForwarders").val("https://cloudflare-dns.com/dns-query ([2606:4700:4700::1111])\r\nhttps://cloudflare-dns.com/dns-query ([2606:4700:4700::1001])");
                $("#rdForwarderProtocolHttps").prop("checked", true);
                break;

            case "cloudflare-tor":
                $("#txtForwarders").val("dns4torpnlfs2ifuz2s2yf3fc7rdmsbhm6rw75euj35pac6ap25zgqad.onion");
                $("#rdForwarderProtocolTcp").prop("checked", true);

                if ($('input[name=rdProxyType]:checked').val() !== "Socks5") {
                    $("#rdProxyTypeSocks5").prop("checked", true);
                    $("#txtProxyAddress").val("127.0.0.1");
                    $("#txtProxyPort").val("9150");
                    $("#txtProxyAddress").prop("disabled", false);
                    $("#txtProxyPort").prop("disabled", false);
                    $("#txtProxyUsername").prop("disabled", false);
                    $("#txtProxyPassword").prop("disabled", false);
                }

                break;

            case "google-udp":
                $("#txtForwarders").val("8.8.8.8\r\n8.8.4.4");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;

            case "google-udp-ipv6":
                $("#txtForwarders").val("[2001:4860:4860::8888]\r\n[2001:4860:4860::8844]");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;

            case "google-tcp":
                $("#txtForwarders").val("8.8.8.8\r\n8.8.4.4");
                $("#rdForwarderProtocolTcp").prop("checked", true);
                break;

            case "google-tcp-ipv6":
                $("#txtForwarders").val("[2001:4860:4860::8888]\r\n[2001:4860:4860::8844]");
                $("#rdForwarderProtocolTcp").prop("checked", true);
                break;

            case "google-tls":
                $("#txtForwarders").val("dns.google (8.8.8.8:853)\r\ndns.google (8.8.4.4:853)");
                $("#rdForwarderProtocolTls").prop("checked", true);
                break;

            case "google-tls-ipv6":
                $("#txtForwarders").val("dns.google ([2001:4860:4860::8888]:853)\r\ndns.google ([2001:4860:4860::8844]:853)");
                $("#rdForwarderProtocolTls").prop("checked", true);
                break;

            case "google-https":
                $("#txtForwarders").val("https://dns.google/dns-query (8.8.8.8)\r\nhttps://dns.google/dns-query (8.8.4.4)");
                $("#rdForwarderProtocolHttps").prop("checked", true);
                break;

            case "google-https-ipv6":
                $("#txtForwarders").val("https://dns.google/dns-query ([2001:4860:4860::8888])\r\nhttps://dns.google/dns-query ([2001:4860:4860::8844])");
                $("#rdForwarderProtocolHttps").prop("checked", true);
                break;


            case "quad9-udp":
                $("#txtForwarders").val("9.9.9.9\r\n149.112.112.112");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;

            case "quad9-udp-ipv6":
                $("#txtForwarders").val("[2620:fe::fe]\r\n[2620:fe::9]");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;

            case "quad9-tcp":
                $("#txtForwarders").val("9.9.9.9\r\n149.112.112.112");
                $("#rdForwarderProtocolTcp").prop("checked", true);
                break;

            case "quad9-tcp-ipv6":
                $("#txtForwarders").val("[2620:fe::fe]\r\n[2620:fe::9]");
                $("#rdForwarderProtocolTcp").prop("checked", true);
                break;

            case "quad9-tls":
                $("#txtForwarders").val("dns.quad9.net (9.9.9.9:853)\r\ndns.quad9.net (149.112.112.112:853)");
                $("#rdForwarderProtocolTls").prop("checked", true);
                break;

            case "quad9-tls-ipv6":
                $("#txtForwarders").val("dns.quad9.net ([2620:fe::fe]:853)\r\ndns.quad9.net ([2620:fe::9]:853)");
                $("#rdForwarderProtocolTls").prop("checked", true);
                break;

            case "quad9-https":
                $("#txtForwarders").val("https://dns.quad9.net/dns-query (9.9.9.9)\r\nhttps://dns.quad9.net/dns-query (149.112.112.112)");
                $("#rdForwarderProtocolHttps").prop("checked", true);
                break;

            case "quad9-https-ipv6":
                $("#txtForwarders").val("https://dns.quad9.net/dns-query ([2620:fe::fe])\r\nhttps://dns.quad9.net/dns-query ([2620:fe::9])");
                $("#rdForwarderProtocolHttps").prop("checked", true);
                break;


            case "quad9-unsecure-udp":
                $("#txtForwarders").val("9.9.9.10\r\n149.112.112.10");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;

            case "quad9-unsecure-udp-ipv6":
                $("#txtForwarders").val("[2620:fe::10]\r\n[2620:fe::fe:10]");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;

            case "quad9-unsecure-tcp":
                $("#txtForwarders").val("9.9.9.10\r\n149.112.112.10");
                $("#rdForwarderProtocolTcp").prop("checked", true);
                break;

            case "quad9-unsecure-tcp-ipv6":
                $("#txtForwarders").val("[2620:fe::10]\r\n[2620:fe::fe:10]");
                $("#rdForwarderProtocolTcp").prop("checked", true);
                break;

            case "quad9-unsecure-tls":
                $("#txtForwarders").val("dns10.quad9.net (9.9.9.10:853)\r\ndns10.quad9.net (149.112.112.10:853)");
                $("#rdForwarderProtocolTls").prop("checked", true);
                break;

            case "quad9-unsecure-tls-ipv6":
                $("#txtForwarders").val("dns10.quad9.net ([2620:fe::10]:853)\r\ndns10.quad9.net ([2620:fe::fe:10]:853)");
                $("#rdForwarderProtocolTls").prop("checked", true);
                break;

            case "quad9-unsecure-https":
                $("#txtForwarders").val("https://dns10.quad9.net/dns-query (9.9.9.10)\r\nhttps://dns10.quad9.net/dns-query (149.112.112.10)");
                $("#rdForwarderProtocolHttps").prop("checked", true);
                break;

            case "quad9-unsecure-https-ipv6":
                $("#txtForwarders").val("https://dns10.quad9.net/dns-query ([2620:fe::10])\r\nhttps://dns10.quad9.net/dns-query ([2620:fe::fe:10])");
                $("#rdForwarderProtocolHttps").prop("checked", true);
                break;


            case "opendns-udp":
                $("#txtForwarders").val("208.67.222.222\r\n208.67.220.220");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;

            case "opendns-udp-ipv6":
                $("#txtForwarders").val("[2620:0:ccc::2]\r\n[2620:0:ccd::2]");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;

            case "opendns-tcp":
                $("#txtForwarders").val("208.67.222.222\r\n208.67.220.220");
                $("#rdForwarderProtocolTcp").prop("checked", true);
                break;

            case "opendns-tcp-ipv6":
                $("#txtForwarders").val("[2620:0:ccc::2]\r\n[2620:0:ccd::2]");
                $("#rdForwarderProtocolTcp").prop("checked", true);
                break;

            case "opendns-tls":
                $("#txtForwarders").val("dns.opendns.com (208.67.222.222:853)\r\ndns.opendns.com (208.67.220.220:853)");
                $("#rdForwarderProtocolTls").prop("checked", true);
                break;

            case "opendns-tls-ipv6":
                $("#txtForwarders").val("dns.opendns.com ([2620:0:ccc::2]:853)\r\ndns.opendns.com ([2620:0:ccd::2]:853)");
                $("#rdForwarderProtocolTls").prop("checked", true);
                break;

            case "opendns-https":
                $("#txtForwarders").val("https://doh.opendns.com/dns-query");
                $("#rdForwarderProtocolHttps").prop("checked", true);
                break;


            case "opendns-fs-udp":
                $("#txtForwarders").val("208.67.222.123\r\n208.67.220.123");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;

            case "opendns-fs-udp-ipv6":
                $("#txtForwarders").val("[2620:119:35::123]\r\n[2620:119:53::123]");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;

            case "opendns-fs-tcp":
                $("#txtForwarders").val("208.67.222.123\r\n208.67.220.123");
                $("#rdForwarderProtocolTcp").prop("checked", true);
                break;

            case "opendns-fs-tcp-ipv6":
                $("#txtForwarders").val("[2620:119:35::123]\r\n[2620:119:53::123]");
                $("#rdForwarderProtocolTcp").prop("checked", true);
                break;

            case "opendns-fs-tls":
                $("#txtForwarders").val("dns.opendns.com (208.67.222.123:853)\r\ndns.opendns.com (208.67.220.123:853)");
                $("#rdForwarderProtocolTls").prop("checked", true);
                break;

            case "opendns-fs-tls-ipv6":
                $("#txtForwarders").val("dns.opendns.com ([2620:119:35::123]:853)\r\ndns.opendns.com ([2620:119:53::123]:853)");
                $("#rdForwarderProtocolTls").prop("checked", true);
                break;

            case "opendns-fs-https":
                $("#txtForwarders").val("https://doh.familyshield.opendns.com/dns-query");
                $("#rdForwarderProtocolHttps").prop("checked", true);
                break;


            case "adguard-udp":
                $("#txtForwarders").val("94.140.14.14\r\n94.140.15.15");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;

            case "adguard-udp-ipv6":
                $("#txtForwarders").val("[2a10:50c0::ad1:ff]\r\n[2a10:50c0::ad2:ff]");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;

            case "adguard-tcp":
                $("#txtForwarders").val("94.140.14.14\r\n94.140.15.15");
                $("#rdForwarderProtocolTcp").prop("checked", true);
                break;

            case "adguard-tcp-ipv6":
                $("#txtForwarders").val("[2a10:50c0::ad1:ff]\r\n[2a10:50c0::ad2:ff]");
                $("#rdForwarderProtocolTcp").prop("checked", true);
                break;

            case "adguard-tls":
                $("#txtForwarders").val("dns.adguard-dns.com (94.140.14.14:853)\r\ndns.adguard-dns.com (94.140.15.15:853)");
                $("#rdForwarderProtocolTls").prop("checked", true);
                break;

            case "adguard-tls-ipv6":
                $("#txtForwarders").val("dns.adguard-dns.com ([2a10:50c0::ad1:ff]:853)\r\ndns.adguard-dns.com ([2a10:50c0::ad2:ff]:853)");
                $("#rdForwarderProtocolTls").prop("checked", true);
                break;

            case "adguard-https":
                $("#txtForwarders").val("https://dns.adguard-dns.com/dns-query");
                $("#rdForwarderProtocolHttps").prop("checked", true);
                break;

            case "adguard-quic":
                $("#txtForwarders").val("dns.adguard-dns.com (94.140.14.14:853)\r\ndns.adguard-dns.com (94.140.15.15:853)");
                $("#rdForwarderProtocolQuic").prop("checked", true);
                break;

            case "adguard-quic-ipv6":
                $("#txtForwarders").val("dns.adguard-dns.com ([2a10:50c0::ad1:ff]:853)\r\ndns.adguard-dns.com ([2a10:50c0::ad2:ff]:853)");
                $("#rdForwarderProtocolQuic").prop("checked", true);
                break;


            case "adguard-f-udp":
                $("#txtForwarders").val("94.140.14.15\r\n94.140.15.16");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;

            case "adguard-f-udp-ipv6":
                $("#txtForwarders").val("[2a10:50c0::bad1:ff]\r\n[2a10:50c0::bad2:ff]");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;

            case "adguard-f-tcp":
                $("#txtForwarders").val("94.140.14.15\r\n94.140.15.16");
                $("#rdForwarderProtocolTcp").prop("checked", true);
                break;

            case "adguard-f-tcp-ipv6":
                $("#txtForwarders").val("[2a10:50c0::bad1:ff]\r\n[2a10:50c0::bad2:ff]");
                $("#rdForwarderProtocolTcp").prop("checked", true);
                break;

            case "adguard-f-tls":
                $("#txtForwarders").val("family.adguard-dns.com (94.140.14.15:853)\r\nfamily.adguard-dns.com (94.140.15.16:853)");
                $("#rdForwarderProtocolTls").prop("checked", true);
                break;

            case "adguard-f-tls-ipv6":
                $("#txtForwarders").val("family.adguard-dns.com ([2a10:50c0::bad1:ff]:853)\r\nfamily.adguard-dns.com ([2a10:50c0::bad2:ff]:853)");
                $("#rdForwarderProtocolTls").prop("checked", true);
                break;

            case "adguard-f-https":
                $("#txtForwarders").val("https://family.adguard-dns.com/dns-query");
                $("#rdForwarderProtocolHttps").prop("checked", true);
                break;

            case "adguard-f-quic":
                $("#txtForwarders").val("family.adguard-dns.com (94.140.14.15:853)\r\nfamily.adguard-dns.com (94.140.15.16:853)");
                $("#rdForwarderProtocolQuic").prop("checked", true);
                break;

            case "adguard-f-quic-ipv6":
                $("#txtForwarders").val("family.adguard-dns.com ([2a10:50c0::bad1:ff]:853)\r\nfamily.adguard-dns.com ([2a10:50c0::bad2:ff]:853)");
                $("#rdForwarderProtocolQuic").prop("checked", true);
                break;


            case "none":
                $("#txtForwarders").val("");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;
        }
    });

    $("input[type=radio][name=rdStatType]").change(function () {
        var type = $('input[name=rdStatType]:checked').val();
        if (type === "custom") {
            $("#divCustomDayWise").show();

            if ($("#dpCustomDayWiseStart").val() === "") {
                $("#dpCustomDayWiseStart").focus();
                return;
            }

            if ($("#dpCustomDayWiseEnd").val() === "") {
                $("#dpCustomDayWiseEnd").focus();
                return;
            }

            refreshDashboard();
        }
        else {
            $("#divCustomDayWise").hide();

            refreshDashboard();
        }
    });

    $("#btnCustomDayWise").click(function () {
        refreshDashboard();
    });
});

function showAbout() {
    if ($("#pageLogin").is(":visible")) {
        window.open("https://technitium.com/aboutus.html", "_blank");
    }
    else {
        $("#mainPanelTabListDashboard").removeClass("active");
        $("#mainPanelTabPaneDashboard").removeClass("active");

        $("#mainPanelTabListZones").removeClass("active");
        $("#mainPanelTabPaneZones").removeClass("active");

        $("#mainPanelTabListCachedZones").removeClass("active");
        $("#mainPanelTabPaneCachedZones").removeClass("active");

        $("#mainPanelTabListAllowedZones").removeClass("active");
        $("#mainPanelTabPaneAllowedZones").removeClass("active");

        $("#mainPanelTabListBlockedZones").removeClass("active");
        $("#mainPanelTabPaneBlockedZones").removeClass("active");

        $("#mainPanelTabListApps").removeClass("active");
        $("#mainPanelTabPaneApps").removeClass("active");

        $("#mainPanelTabListDnsClient").removeClass("active");
        $("#mainPanelTabPaneDnsClient").removeClass("active");

        $("#mainPanelTabListSettings").removeClass("active");
        $("#mainPanelTabPaneSettings").removeClass("active");

        $("#mainPanelTabListDhcp").removeClass("active");
        $("#mainPanelTabPaneDhcp").removeClass("active");

        $("#mainPanelTabListAdmin").removeClass("active");
        $("#mainPanelTabPaneAdmin").removeClass("active");

        $("#mainPanelTabListLogs").removeClass("active");
        $("#mainPanelTabPaneLogs").removeClass("active");

        $("#mainPanelTabListAbout").addClass("active");
        $("#mainPanelTabPaneAbout").addClass("active");

        setTimeout(function () {
            window.scroll({
                top: 0,
                left: 0,
                behavior: "smooth"
            });
        }, 500);
    }
}

function checkForUpdate() {
    HTTPRequest({
        url: "/api/user/checkForUpdate?token=" + sessionData.token,
        success: function (responseJSON) {
            var lnkUpdateAvailable = $("#lnkUpdateAvailable");

            if (responseJSON.response.updateAvailable) {
                $("#lblUpdateVersion").text(responseJSON.response.updateVersion);
                $("#lblCurrentVersion").text(responseJSON.response.currentVersion);

                if (responseJSON.response.updateTitle == null)
                    responseJSON.response.updateTitle = "New Update Available!";

                lnkUpdateAvailable.text(responseJSON.response.updateTitle);
                $("#lblUpdateAvailableTitle").text(responseJSON.response.updateTitle);

                var lblUpdateMessage = $("#lblUpdateMessage");
                var lnkUpdateDownload = $("#lnkUpdateDownload");
                var lnkUpdateInstructions = $("#lnkUpdateInstructions");
                var lnkUpdateChangeLog = $("#lnkUpdateChangeLog");

                if (responseJSON.response.updateMessage == null) {
                    lblUpdateMessage.hide();
                }
                else {
                    lblUpdateMessage.text(responseJSON.response.updateMessage);
                    lblUpdateMessage.show();
                }

                if (responseJSON.response.downloadLink == null) {
                    lnkUpdateDownload.hide();
                }
                else {
                    lnkUpdateDownload.attr("href", responseJSON.response.downloadLink);
                    lnkUpdateDownload.show();
                }

                if (responseJSON.response.instructionsLink == null) {
                    lnkUpdateInstructions.hide();
                }
                else {
                    lnkUpdateInstructions.attr("href", responseJSON.response.instructionsLink);
                    lnkUpdateInstructions.show();
                }

                if (responseJSON.response.changeLogLink == null) {
                    lnkUpdateChangeLog.hide();
                }
                else {
                    lnkUpdateChangeLog.attr("href", responseJSON.response.changeLogLink);
                    lnkUpdateChangeLog.show();
                }

                lnkUpdateAvailable.show();
            }
            else {
                lnkUpdateAvailable.hide();
            }
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function refreshDnsSettings() {
    var divDnsSettingsLoader = $("#divDnsSettingsLoader");
    var divDnsSettings = $("#divDnsSettings");

    divDnsSettings.hide();
    divDnsSettingsLoader.show();

    HTTPRequest({
        url: "/api/settings/get?token=" + sessionData.token,
        success: function (responseJSON) {
            loadDnsSettings(responseJSON);
            checkForReverseProxy(responseJSON);

            divDnsSettingsLoader.hide();
            divDnsSettings.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divDnsSettingsLoader
    });
}

function getArrayAsString(array) {
    var value = "";

    for (var i = 0; i < array.length; i++)
        value += array[i] + "\r\n";

    return value;
}

function loadDnsSettings(responseJSON) {
    document.title = responseJSON.response.dnsServerDomain + " - " + "Technitium DNS Server v" + responseJSON.response.version;
    $("#lblAboutVersion").text(responseJSON.response.version);
    sessionData.info.uptimestamp = responseJSON.response.uptimestamp; //update timestamp since server may have restarted during current session
    $("#lblAboutUptime").text(moment(responseJSON.response.uptimestamp).local().format("lll") + " (" + moment(responseJSON.response.uptimestamp).fromNow() + ")");

    //general
    $("#txtDnsServerDomain").val(responseJSON.response.dnsServerDomain);
    $("#lblDnsServerDomain").text(" - " + responseJSON.response.dnsServerDomain);

    var dnsServerLocalEndPoints = responseJSON.response.dnsServerLocalEndPoints;
    if (dnsServerLocalEndPoints == null)
        $("#txtDnsServerLocalEndPoints").val("");
    else
        $("#txtDnsServerLocalEndPoints").val(getArrayAsString(dnsServerLocalEndPoints));

    $("#txtDnsServerIPv4SourceAddresses").val(getArrayAsString(responseJSON.response.dnsServerIPv4SourceAddresses));
    $("#txtDnsServerIPv6SourceAddresses").val(getArrayAsString(responseJSON.response.dnsServerIPv6SourceAddresses));

    $("#txtDefaultRecordTtl").val(responseJSON.response.defaultRecordTtl);
    $("#txtAddEditRecordTtl").attr("placeholder", responseJSON.response.defaultRecordTtl);

    $("#txtDefaultResponsiblePerson").val(responseJSON.response.defaultResponsiblePerson);
    $("#chkUseSoaSerialDateScheme").prop("checked", responseJSON.response.useSoaSerialDateScheme);
    $("#txtMinSoaRefresh").val(responseJSON.response.minSoaRefresh);
    $("#txtMinSoaRetry").val(responseJSON.response.minSoaRetry);

    $("#txtZoneTransferAllowedNetworks").val(getArrayAsString(responseJSON.response.zoneTransferAllowedNetworks));
    $("#txtNotifyAllowedNetworks").val(getArrayAsString(responseJSON.response.notifyAllowedNetworks));

    $("#chkDnsAppsEnableAutomaticUpdate").prop("checked", responseJSON.response.dnsAppsEnableAutomaticUpdate);

    $("#chkPreferIPv6").prop("checked", responseJSON.response.preferIPv6);
    $("#txtEdnsUdpPayloadSize").val(responseJSON.response.udpPayloadSize);
    $("#chkDnssecValidation").prop("checked", responseJSON.response.dnssecValidation);

    $("#chkEDnsClientSubnet").prop("checked", responseJSON.response.eDnsClientSubnet);
    $("#txtEDnsClientSubnetIPv4PrefixLength").prop("disabled", !responseJSON.response.eDnsClientSubnet);
    $("#txtEDnsClientSubnetIPv6PrefixLength").prop("disabled", !responseJSON.response.eDnsClientSubnet);
    $("#txtEDnsClientSubnetIpv4Override").prop("disabled", !responseJSON.response.eDnsClientSubnet);
    $("#txtEDnsClientSubnetIpv6Override").prop("disabled", !responseJSON.response.eDnsClientSubnet);

    $("#txtEDnsClientSubnetIPv4PrefixLength").val(responseJSON.response.eDnsClientSubnetIPv4PrefixLength);
    $("#txtEDnsClientSubnetIPv6PrefixLength").val(responseJSON.response.eDnsClientSubnetIPv6PrefixLength);
    $("#txtEDnsClientSubnetIpv4Override").val(responseJSON.response.eDnsClientSubnetIpv4Override);
    $("#txtEDnsClientSubnetIpv6Override").val(responseJSON.response.eDnsClientSubnetIpv6Override);

    $("#txtQpmLimitRequests").val(responseJSON.response.qpmLimitRequests);
    $("#txtQpmLimitErrors").val(responseJSON.response.qpmLimitErrors);
    $("#txtQpmLimitSampleMinutes").val(responseJSON.response.qpmLimitSampleMinutes);
    $("#txtQpmLimitIPv4PrefixLength").val(responseJSON.response.qpmLimitIPv4PrefixLength);
    $("#txtQpmLimitIPv6PrefixLength").val(responseJSON.response.qpmLimitIPv6PrefixLength);
    $("#txtQpmLimitBypassList").val(getArrayAsString(responseJSON.response.qpmLimitBypassList));

    $("#txtClientTimeout").val(responseJSON.response.clientTimeout);
    $("#txtTcpSendTimeout").val(responseJSON.response.tcpSendTimeout);
    $("#txtTcpReceiveTimeout").val(responseJSON.response.tcpReceiveTimeout);
    $("#txtQuicIdleTimeout").val(responseJSON.response.quicIdleTimeout);
    $("#txtQuicMaxInboundStreams").val(responseJSON.response.quicMaxInboundStreams);
    $("#txtListenBacklog").val(responseJSON.response.listenBacklog);
    $("#txtMaxConcurrentResolutionsPerCore").val(responseJSON.response.maxConcurrentResolutionsPerCore);

    //web service
    var webServiceLocalAddresses = responseJSON.response.webServiceLocalAddresses;
    if (webServiceLocalAddresses == null)
        $("#txtWebServiceLocalAddresses").val("");
    else
        $("#txtWebServiceLocalAddresses").val(getArrayAsString(webServiceLocalAddresses));

    $("#txtWebServiceHttpPort").val(responseJSON.response.webServiceHttpPort);

    $("#chkWebServiceEnableTls").prop("checked", responseJSON.response.webServiceEnableTls);

    $("#chkWebServiceEnableHttp3").prop("disabled", !responseJSON.response.webServiceEnableTls);
    $("#chkWebServiceHttpToTlsRedirect").prop("disabled", !responseJSON.response.webServiceEnableTls);
    $("#chkWebServiceUseSelfSignedTlsCertificate").prop("disabled", !responseJSON.response.webServiceEnableTls);
    $("#txtWebServiceTlsPort").prop("disabled", !responseJSON.response.webServiceEnableTls);
    $("#txtWebServiceTlsCertificatePath").prop("disabled", !responseJSON.response.webServiceEnableTls);
    $("#txtWebServiceTlsCertificatePassword").prop("disabled", !responseJSON.response.webServiceEnableTls);

    $("#chkWebServiceEnableHttp3").prop("checked", responseJSON.response.webServiceEnableHttp3);
    $("#chkWebServiceHttpToTlsRedirect").prop("checked", responseJSON.response.webServiceHttpToTlsRedirect);
    $("#chkWebServiceUseSelfSignedTlsCertificate").prop("checked", responseJSON.response.webServiceUseSelfSignedTlsCertificate);
    $("#txtWebServiceTlsPort").val(responseJSON.response.webServiceTlsPort);
    $("#txtWebServiceTlsCertificatePath").val(responseJSON.response.webServiceTlsCertificatePath);

    if (responseJSON.response.webServiceTlsCertificatePath == null)
        $("#txtWebServiceTlsCertificatePassword").val("");
    else
        $("#txtWebServiceTlsCertificatePassword").val(responseJSON.response.webServiceTlsCertificatePassword);

    $("#txtWebServiceRealIpHeader").val(responseJSON.response.webServiceRealIpHeader);
    $("#lblWebServiceRealIpHeader").text(responseJSON.response.webServiceRealIpHeader);
    $("#lblWebServiceRealIpNginx").text("proxy_set_header " + responseJSON.response.webServiceRealIpHeader + " $remote_addr;");

    //optional protocols
    $("#chkEnableDnsOverUdpProxy").prop("checked", responseJSON.response.enableDnsOverUdpProxy);
    $("#chkEnableDnsOverTcpProxy").prop("checked", responseJSON.response.enableDnsOverTcpProxy);
    $("#chkEnableDnsOverHttp").prop("checked", responseJSON.response.enableDnsOverHttp);
    $("#chkEnableDnsOverTls").prop("checked", responseJSON.response.enableDnsOverTls);
    $("#chkEnableDnsOverHttps").prop("checked", responseJSON.response.enableDnsOverHttps);
    $("#chkEnableDnsOverHttp3").prop("disabled", !responseJSON.response.enableDnsOverHttps);
    $("#chkEnableDnsOverHttp3").prop("checked", responseJSON.response.enableDnsOverHttp3);
    $("#chkEnableDnsOverQuic").prop("checked", responseJSON.response.enableDnsOverQuic);

    $("#txtDnsOverUdpProxyPort").prop("disabled", !responseJSON.response.enableDnsOverUdpProxy);
    $("#txtDnsOverTcpProxyPort").prop("disabled", !responseJSON.response.enableDnsOverTcpProxy);
    $("#txtDnsOverHttpPort").prop("disabled", !responseJSON.response.enableDnsOverHttp);
    $("#txtDnsOverTlsPort").prop("disabled", !responseJSON.response.enableDnsOverTls);
    $("#txtDnsOverHttpsPort").prop("disabled", !responseJSON.response.enableDnsOverHttps);
    $("#txtDnsOverQuicPort").prop("disabled", !responseJSON.response.enableDnsOverQuic);

    $("#txtDnsOverUdpProxyPort").val(responseJSON.response.dnsOverUdpProxyPort);
    $("#txtDnsOverTcpProxyPort").val(responseJSON.response.dnsOverTcpProxyPort);
    $("#txtDnsOverHttpPort").val(responseJSON.response.dnsOverHttpPort);
    $("#txtDnsOverTlsPort").val(responseJSON.response.dnsOverTlsPort);
    $("#txtDnsOverHttpsPort").val(responseJSON.response.dnsOverHttpsPort);
    $("#txtDnsOverQuicPort").val(responseJSON.response.dnsOverQuicPort);

    $("#txtReverseProxyNetworkACL").prop("disabled", !responseJSON.response.enableDnsOverUdpProxy && !responseJSON.response.enableDnsOverTcpProxy && !responseJSON.response.enableDnsOverHttp);
    $("#txtReverseProxyNetworkACL").val(getArrayAsString(responseJSON.response.reverseProxyNetworkACL));

    $("#txtDnsTlsCertificatePath").prop("disabled", !responseJSON.response.enableDnsOverTls && !responseJSON.response.enableDnsOverHttps && !responseJSON.response.enableDnsOverQuic);
    $("#txtDnsTlsCertificatePassword").prop("disabled", !responseJSON.response.enableDnsOverTls && !responseJSON.response.enableDnsOverHttps && !responseJSON.response.enableDnsOverQuic);

    $("#txtDnsTlsCertificatePath").val(responseJSON.response.dnsTlsCertificatePath);

    if (responseJSON.response.dnsTlsCertificatePath == null)
        $("#txtDnsTlsCertificatePassword").val("");
    else
        $("#txtDnsTlsCertificatePassword").val(responseJSON.response.dnsTlsCertificatePassword);

    $("#lblDoHHost").text(window.location.hostname + (responseJSON.response.dnsOverHttpPort == 80 ? "" : ":" + responseJSON.response.dnsOverHttpPort));
    $("#lblDoTHost").text("tls-certificate-domain:" + responseJSON.response.dnsOverTlsPort);
    $("#lblDoQHost").text("tls-certificate-domain:" + responseJSON.response.dnsOverQuicPort);
    $("#lblDoHsHost").text("tls-certificate-domain" + (responseJSON.response.dnsOverHttpsPort == 443 ? "" : ":" + responseJSON.response.dnsOverHttpsPort));

    $("#txtDnsOverHttpRealIpHeader").prop("disabled", !responseJSON.response.enableDnsOverHttp);
    $("#txtDnsOverHttpRealIpHeader").val(responseJSON.response.dnsOverHttpRealIpHeader);
    $("#lblDnsOverHttpRealIpHeader").text(responseJSON.response.dnsOverHttpRealIpHeader);
    $("#lblDnsOverHttpRealIpNginx").text("proxy_set_header " + responseJSON.response.dnsOverHttpRealIpHeader + " $remote_addr;");

    //tsig
    $("#tableTsigKeys").html("");

    if (responseJSON.response.tsigKeys != null) {
        for (var i = 0; i < responseJSON.response.tsigKeys.length; i++) {
            addTsigKeyRow(responseJSON.response.tsigKeys[i].keyName, responseJSON.response.tsigKeys[i].sharedSecret, responseJSON.response.tsigKeys[i].algorithmName);
        }
    }

    //recursion
    $("#txtRecursionNetworkACL").prop("disabled", true);

    switch (responseJSON.response.recursion) {
        case "Allow":
            $("#rdRecursionAllow").prop("checked", true);
            break;

        case "AllowOnlyForPrivateNetworks":
            $("#rdRecursionAllowOnlyForPrivateNetworks").prop("checked", true);
            break;

        case "UseSpecifiedNetworkACL":
            $("#rdRecursionUseSpecifiedNetworkACL").prop("checked", true);
            $("#txtRecursionNetworkACL").prop("disabled", false);
            break;

        case "Deny":
        default:
            $("#rdRecursionDeny").prop("checked", true);
            break;
    }

    $("#txtRecursionNetworkACL").val(getArrayAsString(responseJSON.response.recursionNetworkACL));

    $("#chkRandomizeName").prop("checked", responseJSON.response.randomizeName);
    $("#chkQnameMinimization").prop("checked", responseJSON.response.qnameMinimization);
    $("#chkNsRevalidation").prop("checked", responseJSON.response.nsRevalidation);

    $("#txtResolverRetries").val(responseJSON.response.resolverRetries);
    $("#txtResolverTimeout").val(responseJSON.response.resolverTimeout);
    $("#txtResolverConcurrency").val(responseJSON.response.resolverConcurrency);
    $("#txtResolverMaxStackCount").val(responseJSON.response.resolverMaxStackCount);

    //cache
    $("#chkSaveCache").prop("checked", responseJSON.response.saveCache);

    $("#chkServeStale").prop("checked", responseJSON.response.serveStale);
    $("#txtServeStaleTtl").prop("disabled", !responseJSON.response.serveStale);
    $("#txtServeStaleTtl").val(responseJSON.response.serveStaleTtl);
    $("#txtServeStaleAnswerTtl").val(responseJSON.response.serveStaleAnswerTtl);
    $("#txtServeStaleResetTtl").val(responseJSON.response.serveStaleResetTtl);
    $("#txtServeStaleMaxWaitTime").val(responseJSON.response.serveStaleMaxWaitTime);

    $("#txtCacheMaximumEntries").val(responseJSON.response.cacheMaximumEntries);
    $("#txtCacheMinimumRecordTtl").val(responseJSON.response.cacheMinimumRecordTtl);
    $("#txtCacheMaximumRecordTtl").val(responseJSON.response.cacheMaximumRecordTtl);
    $("#txtCacheNegativeRecordTtl").val(responseJSON.response.cacheNegativeRecordTtl);
    $("#txtCacheFailureRecordTtl").val(responseJSON.response.cacheFailureRecordTtl);

    $("#txtCachePrefetchEligibility").val(responseJSON.response.cachePrefetchEligibility);
    $("#txtCachePrefetchTrigger").val(responseJSON.response.cachePrefetchTrigger);
    $("#txtCachePrefetchSampleIntervalInMinutes").val(responseJSON.response.cachePrefetchSampleIntervalInMinutes);
    $("#txtCachePrefetchSampleEligibilityHitsPerHour").val(responseJSON.response.cachePrefetchSampleEligibilityHitsPerHour);

    //blocking
    $("#chkEnableBlocking").prop("checked", responseJSON.response.enableBlocking);

    $("#chkAllowTxtBlockingReport").prop("disabled", !responseJSON.response.enableBlocking);
    $("#txtTemporaryDisableBlockingMinutes").prop("disabled", !responseJSON.response.enableBlocking);
    $("#btnTemporaryDisableBlockingNow").prop("disabled", !responseJSON.response.enableBlocking);
    $("#txtBlockingBypassList").prop("disabled", !responseJSON.response.enableBlocking);
    $("#rdBlockingTypeAnyAddress").prop("disabled", !responseJSON.response.enableBlocking);
    $("#rdBlockingTypeNxDomain").prop("disabled", !responseJSON.response.enableBlocking);
    $("#rdBlockingTypeCustomAddress").prop("disabled", !responseJSON.response.enableBlocking);
    $("#txtBlockListUrls").prop("disabled", !responseJSON.response.enableBlocking);
    $("#optQuickBlockList").prop("disabled", !responseJSON.response.enableBlocking);
    $("#txtBlockListUpdateIntervalHours").prop("disabled", !responseJSON.response.enableBlocking);

    $("#chkAllowTxtBlockingReport").prop("checked", responseJSON.response.allowTxtBlockingReport);

    if (responseJSON.response.temporaryDisableBlockingTill == null)
        $("#lblTemporaryDisableBlockingTill").text("Not Set");
    else
        $("#lblTemporaryDisableBlockingTill").text(moment(responseJSON.response.temporaryDisableBlockingTill).local().format("YYYY-MM-DD HH:mm:ss"));

    $("#txtTemporaryDisableBlockingMinutes").val("");

    $("#txtCustomBlockingAddresses").prop("disabled", true);

    $("#txtBlockingBypassList").val(getArrayAsString(responseJSON.response.blockingBypassList));

    switch (responseJSON.response.blockingType) {
        case "NxDomain":
            $("#rdBlockingTypeNxDomain").prop("checked", true);
            break;

        case "CustomAddress":
            $("#rdBlockingTypeCustomAddress").prop("checked", true);
            $("#txtCustomBlockingAddresses").prop("disabled", !responseJSON.response.enableBlocking);
            break;

        case "AnyAddress":
        default:
            $("#rdBlockingTypeAnyAddress").prop("checked", true);
            break;
    }

    $("#txtCustomBlockingAddresses").val(getArrayAsString(responseJSON.response.customBlockingAddresses));

    $("#txtBlockingAnswerTtl").val(responseJSON.response.blockingAnswerTtl);

    var blockListUrls = responseJSON.response.blockListUrls;
    if (blockListUrls == null) {
        $("#txtBlockListUrls").val("");
        $("#btnUpdateBlockListsNow").prop("disabled", true);
    }
    else {
        $("#txtBlockListUrls").val(getArrayAsString(blockListUrls));
        $("#btnUpdateBlockListsNow").prop("disabled", !responseJSON.response.enableBlocking);
    }

    $("#optQuickBlockList").val("blank");

    $("#txtBlockListUpdateIntervalHours").val(responseJSON.response.blockListUpdateIntervalHours);

    if (responseJSON.response.blockListNextUpdatedOn == null) {
        $("#lblBlockListNextUpdatedOn").text("Not Scheduled");
    }
    else {
        var blockListNextUpdatedOn = moment(responseJSON.response.blockListNextUpdatedOn);

        if (moment().utc().isBefore(blockListNextUpdatedOn))
            $("#lblBlockListNextUpdatedOn").text(blockListNextUpdatedOn.local().format("YYYY-MM-DD HH:mm:ss"));
        else
            $("#lblBlockListNextUpdatedOn").text("Updating Now");
    }

    //proxy & forwarders
    var proxy = responseJSON.response.proxy;
    if (proxy === null) {
        $("#rdProxyTypeNone").prop("checked", true);

        $("#txtProxyAddress").prop("disabled", true);
        $("#txtProxyPort").prop("disabled", true);
        $("#txtProxyUsername").prop("disabled", true);
        $("#txtProxyPassword").prop("disabled", true);
        $("#txtProxyBypassList").prop("disabled", true);

        $("#txtProxyAddress").val("");
        $("#txtProxyPort").val("");
        $("#txtProxyUsername").val("");
        $("#txtProxyPassword").val("");
        $("#txtProxyBypassList").val("");
    }
    else {
        switch (proxy.type.toLowerCase()) {
            case "http":
                $("#rdProxyTypeHttp").prop("checked", true);
                break;

            case "socks5":
                $("#rdProxyTypeSocks5").prop("checked", true);
                break;

            default:
                $("#rdProxyTypeNone").prop("checked", true);
                break;
        }

        $("#txtProxyAddress").val(proxy.address);
        $("#txtProxyPort").val(proxy.port);
        $("#txtProxyUsername").val(proxy.username);
        $("#txtProxyPassword").val(proxy.password);
        $("#txtProxyBypassList").val(getArrayAsString(proxy.bypass));

        $("#txtProxyAddress").prop("disabled", false);
        $("#txtProxyPort").prop("disabled", false);
        $("#txtProxyUsername").prop("disabled", false);
        $("#txtProxyPassword").prop("disabled", false);
        $("#txtProxyBypassList").prop("disabled", false);
    }

    var forwarders = responseJSON.response.forwarders;
    if (forwarders == null)
        $("#txtForwarders").val("");
    else
        $("#txtForwarders").val(getArrayAsString(forwarders));

    $("#optQuickForwarders").val("blank");

    switch (responseJSON.response.forwarderProtocol.toLowerCase()) {
        case "tcp":
            $("#rdForwarderProtocolTcp").prop("checked", true);
            break;

        case "tls":
            $("#rdForwarderProtocolTls").prop("checked", true);
            break;

        case "https":
            $("#rdForwarderProtocolHttps").prop("checked", true);
            break;

        case "quic":
            $("#rdForwarderProtocolQuic").prop("checked", true);
            break;

        default:
            $("#rdForwarderProtocolUdp").prop("checked", true);
            break;
    }

    $("#chkEnableConcurrentForwarding").prop("checked", responseJSON.response.concurrentForwarding);
    $("#txtForwarderConcurrency").prop("disabled", !responseJSON.response.concurrentForwarding)

    $("#txtForwarderRetries").val(responseJSON.response.forwarderRetries);
    $("#txtForwarderTimeout").val(responseJSON.response.forwarderTimeout);
    $("#txtForwarderConcurrency").val(responseJSON.response.forwarderConcurrency);

    //logging
    $("#chkEnableLogging").prop("checked", responseJSON.response.enableLogging);

    $("#chkIgnoreResolverLogs").prop("disabled", !responseJSON.response.enableLogging);
    $("#chkLogQueries").prop("disabled", !responseJSON.response.enableLogging);
    $("#chkUseLocalTime").prop("disabled", !responseJSON.response.enableLogging);
    $("#txtLogFolderPath").prop("disabled", !responseJSON.response.enableLogging);

    $("#chkIgnoreResolverLogs").prop("checked", responseJSON.response.ignoreResolverLogs);
    $("#chkLogQueries").prop("checked", responseJSON.response.logQueries);
    $("#chkUseLocalTime").prop("checked", responseJSON.response.useLocalTime);
    $("#txtLogFolderPath").val(responseJSON.response.logFolder);
    $("#txtMaxLogFileDays").val(responseJSON.response.maxLogFileDays);

    $("#chkEnableInMemoryStats").prop("checked", responseJSON.response.enableInMemoryStats);
    $("#txtMaxStatFileDays").val(responseJSON.response.maxStatFileDays);
}

function saveDnsSettings() {
    //general
    var dnsServerDomain = $("#txtDnsServerDomain").val();

    if ((dnsServerDomain === null) || (dnsServerDomain === "")) {
        showAlert("warning", "Missing!", "Please enter server domain name.");
        $("#txtDnsServerDomain").focus();
        return;
    }

    var dnsServerLocalEndPoints = cleanTextList($("#txtDnsServerLocalEndPoints").val());

    if ((dnsServerLocalEndPoints.length === 0) || (dnsServerLocalEndPoints === ","))
        dnsServerLocalEndPoints = "0.0.0.0:53,[::]:53";
    else
        $("#txtDnsServerLocalEndPoints").val(dnsServerLocalEndPoints.replace(/,/g, "\n"));

    var dnsServerIPv4SourceAddresses = cleanTextList($("#txtDnsServerIPv4SourceAddresses").val());
    if ((dnsServerIPv4SourceAddresses.length == 0) || (dnsServerIPv4SourceAddresses === ","))
        dnsServerIPv4SourceAddresses = false;

    var dnsServerIPv6SourceAddresses = cleanTextList($("#txtDnsServerIPv6SourceAddresses").val());
    if ((dnsServerIPv6SourceAddresses.length == 0) || (dnsServerIPv6SourceAddresses === ","))
        dnsServerIPv6SourceAddresses = false;

    var defaultRecordTtl = $("#txtDefaultRecordTtl").val();
    var defaultResponsiblePerson = $("#txtDefaultResponsiblePerson").val();
    var useSoaSerialDateScheme = $("#chkUseSoaSerialDateScheme").prop("checked");
    var minSoaRefresh = $("#txtMinSoaRefresh").val();
    var minSoaRetry = $("#txtMinSoaRetry").val();

    var zoneTransferAllowedNetworks = cleanTextList($("#txtZoneTransferAllowedNetworks").val());
    if ((zoneTransferAllowedNetworks.length == 0) || (zoneTransferAllowedNetworks === ","))
        zoneTransferAllowedNetworks = false;
    else
        $("#txtZoneTransferAllowedNetworks").val(zoneTransferAllowedNetworks.replace(/,/g, "\n") + "\n");

    var notifyAllowedNetworks = cleanTextList($("#txtNotifyAllowedNetworks").val());
    if ((notifyAllowedNetworks.length == 0) || (notifyAllowedNetworks === ","))
        notifyAllowedNetworks = false;
    else
        $("#txtNotifyAllowedNetworks").val(notifyAllowedNetworks.replace(/,/g, "\n") + "\n");

    var dnsAppsEnableAutomaticUpdate = $("#chkDnsAppsEnableAutomaticUpdate").prop('checked');
    var preferIPv6 = $("#chkPreferIPv6").prop('checked');
    var udpPayloadSize = $("#txtEdnsUdpPayloadSize").val();
    var dnssecValidation = $("#chkDnssecValidation").prop('checked');

    var eDnsClientSubnet = $("#chkEDnsClientSubnet").prop("checked");

    var eDnsClientSubnetIPv4PrefixLength = $("#txtEDnsClientSubnetIPv4PrefixLength").val();
    if ((eDnsClientSubnetIPv4PrefixLength == null) || (eDnsClientSubnetIPv4PrefixLength === "")) {
        showAlert("warning", "Missing!", "Please enter EDNS Client Subnet IPv4 prefix length.");
        $("#txtEDnsClientSubnetIPv4PrefixLength").focus();
        return;
    }

    var eDnsClientSubnetIPv6PrefixLength = $("#txtEDnsClientSubnetIPv6PrefixLength").val();
    if ((eDnsClientSubnetIPv6PrefixLength == null) || (eDnsClientSubnetIPv6PrefixLength === "")) {
        showAlert("warning", "Missing!", "Please enter EDNS Client Subnet IPv6 prefix length.");
        $("#txtEDnsClientSubnetIPv6PrefixLength").focus();
        return;
    }

    var eDnsClientSubnetIpv4Override = $("#txtEDnsClientSubnetIpv4Override").val();
    var eDnsClientSubnetIpv6Override = $("#txtEDnsClientSubnetIpv6Override").val();

    var qpmLimitRequests = $("#txtQpmLimitRequests").val();
    if ((qpmLimitRequests == null) || (qpmLimitRequests === "")) {
        showAlert("warning", "Missing!", "Please enter Queries Per Minute (QPM) request limit value.");
        $("#txtQpmLimitRequests").focus();
        return;
    }

    var qpmLimitErrors = $("#txtQpmLimitErrors").val();
    if ((qpmLimitErrors == null) || (qpmLimitErrors === "")) {
        showAlert("warning", "Missing!", "Please enter Queries Per Minute (QPM) error limit value.");
        $("#txtQpmLimitErrors").focus();
        return;
    }

    var qpmLimitSampleMinutes = $("#txtQpmLimitSampleMinutes").val();
    if ((qpmLimitSampleMinutes == null) || (qpmLimitSampleMinutes === "")) {
        showAlert("warning", "Missing!", "Please enter Queries Per Minute (QPM) sample value.");
        $("#txtQpmLimitSampleMinutes").focus();
        return;
    }

    var qpmLimitIPv4PrefixLength = $("#txtQpmLimitIPv4PrefixLength").val();
    if ((qpmLimitIPv4PrefixLength == null) || (qpmLimitIPv4PrefixLength === "")) {
        showAlert("warning", "Missing!", "Please enter Queries Per Minute (QPM) limit IPv4 prefix length.");
        $("#txtQpmLimitIPv4PrefixLength").focus();
        return;
    }

    var qpmLimitIPv6PrefixLength = $("#txtQpmLimitIPv6PrefixLength").val();
    if ((qpmLimitIPv6PrefixLength == null) || (qpmLimitIPv6PrefixLength === "")) {
        showAlert("warning", "Missing!", "Please enter Queries Per Minute (QPM) limit IPv6 prefix length.");
        $("#txtQpmLimitIPv6PrefixLength").focus();
        return;
    }

    var qpmLimitBypassList = cleanTextList($("#txtQpmLimitBypassList").val());
    if ((qpmLimitBypassList.length == 0) || (qpmLimitBypassList === ","))
        qpmLimitBypassList = false;
    else
        $("#txtQpmLimitBypassList").val(qpmLimitBypassList.replace(/,/g, "\n") + "\n");

    var clientTimeout = $("#txtClientTimeout").val();
    if ((clientTimeout == null) || (clientTimeout === "")) {
        showAlert("warning", "Missing!", "Please enter a value for Client Timeout.");
        $("#txtClientTimeout").focus();
        return;
    }

    var tcpSendTimeout = $("#txtTcpSendTimeout").val();
    if ((tcpSendTimeout == null) || (tcpSendTimeout === "")) {
        showAlert("warning", "Missing!", "Please enter a value for TCP Send Timeout.");
        $("#txtTcpSendTimeout").focus();
        return;
    }

    var tcpReceiveTimeout = $("#txtTcpReceiveTimeout").val();
    if ((tcpReceiveTimeout == null) || (tcpReceiveTimeout === "")) {
        showAlert("warning", "Missing!", "Please enter a value for TCP Receive Timeout.");
        $("#txtTcpReceiveTimeout").focus();
        return;
    }

    var quicIdleTimeout = $("#txtQuicIdleTimeout").val();
    if ((quicIdleTimeout == null) || (quicIdleTimeout === "")) {
        showAlert("warning", "Missing!", "Please enter a value for QUIC Idle Timeout.");
        $("#txtQuicIdleTimeout").focus();
        return;
    }

    var quicMaxInboundStreams = $("#txtQuicMaxInboundStreams").val();
    if ((quicMaxInboundStreams == null) || (quicMaxInboundStreams === "")) {
        showAlert("warning", "Missing!", "Please enter a value for QUIC Max Inbound Streams.");
        $("#txtQuicMaxInboundStreams").focus();
        return;
    }

    var listenBacklog = $("#txtListenBacklog").val();
    if ((listenBacklog == null) || (listenBacklog === "")) {
        showAlert("warning", "Missing!", "Please enter a value for Listen Backlog.");
        $("#txtListenBacklog").focus();
        return;
    }

    var maxConcurrentResolutionsPerCore = $("#txtMaxConcurrentResolutionsPerCore").val();
    if ((maxConcurrentResolutionsPerCore == null) || (maxConcurrentResolutionsPerCore === "")) {
        showAlert("warning", "Missing!", "Please enter a value for Max Concurrent Resolutions.");
        $("#txtMaxConcurrentResolutionsPerCore").focus();
        return;
    }

    //web service
    var webServiceLocalAddresses = cleanTextList($("#txtWebServiceLocalAddresses").val());

    if ((webServiceLocalAddresses.length === 0) || (webServiceLocalAddresses === ","))
        webServiceLocalAddresses = "0.0.0.0,[::]";
    else
        $("#txtWebServiceLocalAddresses").val(webServiceLocalAddresses.replace(/,/g, "\n"));

    var webServiceHttpPort = $("#txtWebServiceHttpPort").val();

    if ((webServiceHttpPort === null) || (webServiceHttpPort === ""))
        webServiceHttpPort = 5380;

    var webServiceEnableTls = $("#chkWebServiceEnableTls").prop("checked");
    var webServiceEnableHttp3 = $("#chkWebServiceEnableHttp3").prop("checked");
    var webServiceHttpToTlsRedirect = $("#chkWebServiceHttpToTlsRedirect").prop("checked");
    var webServiceUseSelfSignedTlsCertificate = $("#chkWebServiceUseSelfSignedTlsCertificate").prop("checked");
    var webServiceTlsPort = $("#txtWebServiceTlsPort").val();
    var webServiceTlsCertificatePath = $("#txtWebServiceTlsCertificatePath").val();
    var webServiceTlsCertificatePassword = $("#txtWebServiceTlsCertificatePassword").val();
    var webServiceRealIpHeader = $("#txtWebServiceRealIpHeader").val();

    //optional protocols
    var enableDnsOverUdpProxy = $("#chkEnableDnsOverUdpProxy").prop("checked");
    var enableDnsOverTcpProxy = $("#chkEnableDnsOverTcpProxy").prop("checked");
    var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
    var enableDnsOverTls = $("#chkEnableDnsOverTls").prop("checked");
    var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");
    var enableDnsOverHttp3 = $("#chkEnableDnsOverHttp3").prop("checked");
    var enableDnsOverQuic = $("#chkEnableDnsOverQuic").prop("checked");

    var dnsOverUdpProxyPort = $("#txtDnsOverUdpProxyPort").val();
    if ((dnsOverUdpProxyPort == null) || (dnsOverUdpProxyPort === "")) {
        showAlert("warning", "Missing!", "Please enter a value for DNS-over-UDP-PROXY Port.");
        $("#txtDnsOverUdpProxyPort").focus();
        return;
    }

    var dnsOverTcpProxyPort = $("#txtDnsOverTcpProxyPort").val();
    if ((dnsOverTcpProxyPort == null) || (dnsOverTcpProxyPort === "")) {
        showAlert("warning", "Missing!", "Please enter a value for DNS-over-TCP-PROXY Port.");
        $("#txtDnsOverTcpProxyPort").focus();
        return;
    }

    var dnsOverHttpPort = $("#txtDnsOverHttpPort").val();
    if ((dnsOverHttpPort == null) || (dnsOverHttpPort === "")) {
        showAlert("warning", "Missing!", "Please enter a value for DNS-over-HTTP Port.");
        $("#txtDnsOverHttpPort").focus();
        return;
    }

    var dnsOverTlsPort = $("#txtDnsOverTlsPort").val();
    if ((dnsOverTlsPort == null) || (dnsOverTlsPort === "")) {
        showAlert("warning", "Missing!", "Please enter a value for DNS-over-TLS Port.");
        $("#txtDnsOverTlsPort").focus();
        return;
    }

    var dnsOverHttpsPort = $("#txtDnsOverHttpsPort").val();
    if ((dnsOverHttpsPort == null) || (dnsOverHttpsPort === "")) {
        showAlert("warning", "Missing!", "Please enter a value for DNS-over-HTTPS Port.");
        $("#txtDnsOverHttpsPort").focus();
        return;
    }

    var dnsOverQuicPort = $("#txtDnsOverQuicPort").val();
    if ((dnsOverQuicPort == null) || (dnsOverQuicPort === "")) {
        showAlert("warning", "Missing!", "Please enter a value for DNS-over-QUIC Port.");
        $("#txtDnsOverQuicPort").focus();
        return;
    }

    var reverseProxyNetworkACL = cleanTextList($("#txtReverseProxyNetworkACL").val());

    if ((reverseProxyNetworkACL.length === 0) || (reverseProxyNetworkACL === ","))
        reverseProxyNetworkACL = false;
    else
        $("#txtReverseProxyNetworkACL").val(reverseProxyNetworkACL.replace(/,/g, "\n"));

    var dnsTlsCertificatePath = $("#txtDnsTlsCertificatePath").val();
    var dnsTlsCertificatePassword = $("#txtDnsTlsCertificatePassword").val();

    var dnsOverHttpRealIpHeader = $("#txtDnsOverHttpRealIpHeader").val();

    //tsig
    var tsigKeys = serializeTableData($("#tableTsigKeys"), 3);
    if (tsigKeys === false)
        return;

    if (tsigKeys.length === 0)
        tsigKeys = false;

    //recursion
    var recursion = $("input[name=rdRecursion]:checked").val();

    var recursionNetworkACL = cleanTextList($("#txtRecursionNetworkACL").val());

    if ((recursionNetworkACL.length === 0) || (recursionNetworkACL === ","))
        recursionNetworkACL = false;
    else
        $("#txtRecursionNetworkACL").val(recursionNetworkACL.replace(/,/g, "\n"));

    var randomizeName = $("#chkRandomizeName").prop('checked');
    var qnameMinimization = $("#chkQnameMinimization").prop('checked');
    var nsRevalidation = $("#chkNsRevalidation").prop('checked');

    var resolverRetries = $("#txtResolverRetries").val();
    if ((resolverRetries == null) || (resolverRetries === "")) {
        showAlert("warning", "Missing!", "Please enter a value for Resolver Retries.");
        $("#txtResolverRetries").focus();
        return;
    }

    var resolverTimeout = $("#txtResolverTimeout").val();
    if ((resolverTimeout == null) || (resolverTimeout === "")) {
        showAlert("warning", "Missing!", "Please enter a value for Resolver Timeout.");
        $("#txtResolverTimeout").focus();
        return;
    }

    var resolverConcurrency = $("#txtResolverConcurrency").val();
    if ((resolverConcurrency == null) || (resolverConcurrency === "")) {
        showAlert("warning", "Missing!", "Please enter a value for Resolver Concurrency.");
        $("#txtResolverConcurrency").focus();
        return;
    }

    var resolverMaxStackCount = $("#txtResolverMaxStackCount").val();
    if ((resolverMaxStackCount == null) || (resolverMaxStackCount === "")) {
        showAlert("warning", "Missing!", "Please enter a value for Resolver Max Stack Count.");
        $("#txtResolverMaxStackCount").focus();
        return;
    }

    //cache
    var saveCache = $("#chkSaveCache").prop("checked");

    var serveStale = $("#chkServeStale").prop("checked");
    var serveStaleTtl = $("#txtServeStaleTtl").val();
    var serveStaleAnswerTtl = $("#txtServeStaleAnswerTtl").val();
    var serveStaleResetTtl = $("#txtServeStaleResetTtl").val();
    var serveStaleMaxWaitTime = $("#txtServeStaleMaxWaitTime").val();

    var cacheMaximumEntries = $("#txtCacheMaximumEntries").val();
    if ((cacheMaximumEntries === null) || (cacheMaximumEntries === "")) {
        showAlert("warning", "Missing!", "Please enter cache maximum entries value.");
        $("#txtCacheMaximumEntries").focus();
        return;
    }

    var cacheMinimumRecordTtl = $("#txtCacheMinimumRecordTtl").val();
    if ((cacheMinimumRecordTtl === null) || (cacheMinimumRecordTtl === "")) {
        showAlert("warning", "Missing!", "Please enter cache minimum record TTL value.");
        $("#txtCacheMinimumRecordTtl").focus();
        return;
    }

    var cacheMaximumRecordTtl = $("#txtCacheMaximumRecordTtl").val();
    if ((cacheMaximumRecordTtl === null) || (cacheMaximumRecordTtl === "")) {
        showAlert("warning", "Missing!", "Please enter cache maximum record TTL value.");
        $("#txtCacheMaximumRecordTtl").focus();
        return;
    }

    var cacheNegativeRecordTtl = $("#txtCacheNegativeRecordTtl").val();
    if ((cacheNegativeRecordTtl === null) || (cacheNegativeRecordTtl === "")) {
        showAlert("warning", "Missing!", "Please enter cache negative record TTL value.");
        $("#txtCacheNegativeRecordTtl").focus();
        return;
    }

    var cacheFailureRecordTtl = $("#txtCacheFailureRecordTtl").val();
    if ((cacheFailureRecordTtl === null) || (cacheFailureRecordTtl === "")) {
        showAlert("warning", "Missing!", "Please enter cache failure record TTL value.");
        $("#txtCacheFailureRecordTtl").focus();
        return;
    }

    var cachePrefetchEligibility = $("#txtCachePrefetchEligibility").val();
    if ((cachePrefetchEligibility === null) || (cachePrefetchEligibility === "")) {
        showAlert("warning", "Missing!", "Please enter cache prefetch eligibility value.");
        $("#txtCachePrefetchEligibility").focus();
        return;
    }

    var cachePrefetchTrigger = $("#txtCachePrefetchTrigger").val();
    if ((cachePrefetchTrigger === null) || (cachePrefetchTrigger === "")) {
        showAlert("warning", "Missing!", "Please enter cache prefetch trigger value.");
        $("#txtCachePrefetchTrigger").focus();
        return;
    }

    var cachePrefetchSampleIntervalInMinutes = $("#txtCachePrefetchSampleIntervalInMinutes").val();
    if ((cachePrefetchSampleIntervalInMinutes === null) || (cachePrefetchSampleIntervalInMinutes === "")) {
        showAlert("warning", "Missing!", "Please enter cache auto prefetch sample interval value.");
        $("#txtCachePrefetchSampleIntervalInMinutes").focus();
        return;
    }

    var cachePrefetchSampleEligibilityHitsPerHour = $("#txtCachePrefetchSampleEligibilityHitsPerHour").val();
    if ((cachePrefetchSampleEligibilityHitsPerHour === null) || (cachePrefetchSampleEligibilityHitsPerHour === "")) {
        showAlert("warning", "Missing!", "Please enter cache auto prefetch sample eligibility value.");
        $("#txtCachePrefetchSampleEligibilityHitsPerHour").focus();
        return;
    }

    //blocking
    var enableBlocking = $("#chkEnableBlocking").prop("checked");
    var allowTxtBlockingReport = $("#chkAllowTxtBlockingReport").prop("checked");

    var blockingBypassList = cleanTextList($("#txtBlockingBypassList").val());
    if ((blockingBypassList.length == 0) || (blockingBypassList === ","))
        blockingBypassList = false;
    else
        $("#txtBlockingBypassList").val(blockingBypassList.replace(/,/g, "\n") + "\n");

    var blockingType = $("input[name=rdBlockingType]:checked").val();

    var customBlockingAddresses = cleanTextList($("#txtCustomBlockingAddresses").val());
    if ((customBlockingAddresses.length === 0) || customBlockingAddresses === ",")
        customBlockingAddresses = false;
    else
        $("#txtCustomBlockingAddresses").val(customBlockingAddresses.replace(/,/g, "\n") + "\n");

    var blockingAnswerTtl = $("#txtBlockingAnswerTtl").val();

    var blockListUrls = cleanTextList($("#txtBlockListUrls").val());

    if ((blockListUrls.length === 0) || (blockListUrls === ","))
        blockListUrls = false;
    else
        $("#txtBlockListUrls").val(blockListUrls.replace(/,/g, "\n") + "\n");

    var blockListUpdateIntervalHours = $("#txtBlockListUpdateIntervalHours").val();

    //proxy & forwarders
    var proxy;
    var proxyType = $('input[name=rdProxyType]:checked').val().toLowerCase();
    if (proxyType === "none") {
        proxy = "&proxyType=" + proxyType;
    }
    else {
        var proxyAddress = $("#txtProxyAddress").val();

        if ((proxyAddress === null) || (proxyAddress === "")) {
            showAlert("warning", "Missing!", "Please enter proxy server address.");
            $("#txtProxyAddress").focus();
            return;
        }

        var proxyPort = $("#txtProxyPort").val();

        if ((proxyPort === null) || (proxyPort === "")) {
            showAlert("warning", "Missing!", "Please enter proxy server port.");
            $("#txtProxyPort").focus();
            return;
        }

        var proxyBypass = cleanTextList($("#txtProxyBypassList").val());

        if ((proxyBypass.length === 0) || (proxyBypass === ","))
            proxyBypass = "";
        else
            $("#txtProxyBypassList").val(proxyBypass.replace(/,/g, "\n"));

        proxy = "&proxyType=" + proxyType + "&proxyAddress=" + encodeURIComponent(proxyAddress) + "&proxyPort=" + proxyPort + "&proxyUsername=" + encodeURIComponent($("#txtProxyUsername").val()) + "&proxyPassword=" + encodeURIComponent($("#txtProxyPassword").val()) + "&proxyBypass=" + encodeURIComponent(proxyBypass);
    }

    var forwarders = cleanTextList($("#txtForwarders").val());

    if ((forwarders.length === 0) || (forwarders === ","))
        forwarders = false;
    else
        $("#txtForwarders").val(forwarders.replace(/,/g, "\n"));

    var forwarderProtocol = $('input[name=rdForwarderProtocol]:checked').val();

    var concurrentForwarding = $("#chkEnableConcurrentForwarding").prop("checked");

    var forwarderRetries = $("#txtForwarderRetries").val();
    if ((forwarderRetries == null) || (forwarderRetries === "")) {
        showAlert("warning", "Missing!", "Please enter a value for Forwarder Retries.");
        $("#txtForwarderRetries").focus();
        return;
    }

    var forwarderTimeout = $("#txtForwarderTimeout").val();
    if ((forwarderTimeout == null) || (forwarderTimeout === "")) {
        showAlert("warning", "Missing!", "Please enter a value for Forwarder Timeout.");
        $("#txtForwarderTimeout").focus();
        return;
    }

    var forwarderConcurrency = $("#txtForwarderConcurrency").val();
    if ((forwarderConcurrency == null) || (forwarderConcurrency === "")) {
        showAlert("warning", "Missing!", "Please enter a value for Forwarder Concurrency.");
        $("#txtForwarderConcurrency").focus();
        return;
    }

    //logging
    var enableLogging = $("#chkEnableLogging").prop('checked');
    var ignoreResolverLogs = $("#chkIgnoreResolverLogs").prop('checked');
    var logQueries = $("#chkLogQueries").prop('checked');
    var useLocalTime = $("#chkUseLocalTime").prop('checked');
    var logFolder = $("#txtLogFolderPath").val();
    var maxLogFileDays = $("#txtMaxLogFileDays").val();

    var enableInMemoryStats = $("#chkEnableInMemoryStats").prop("checked");
    var maxStatFileDays = $("#txtMaxStatFileDays").val();

    //send request
    var btn = $("#btnSaveDnsSettings").button('loading');

    HTTPRequest({
        url: "/api/settings/set",
        method: "POST",
        data: "token=" + sessionData.token + "&dnsServerDomain=" + dnsServerDomain + "&dnsServerLocalEndPoints=" + encodeURIComponent(dnsServerLocalEndPoints) + "&dnsServerIPv4SourceAddresses=" + encodeURIComponent(dnsServerIPv4SourceAddresses) + "&dnsServerIPv6SourceAddresses=" + encodeURIComponent(dnsServerIPv6SourceAddresses)
            + "&defaultRecordTtl=" + defaultRecordTtl + "&defaultResponsiblePerson=" + encodeURIComponent(defaultResponsiblePerson) + "&useSoaSerialDateScheme=" + useSoaSerialDateScheme + "&minSoaRefresh=" + minSoaRefresh + "&minSoaRetry=" + minSoaRetry + "&zoneTransferAllowedNetworks=" + encodeURIComponent(zoneTransferAllowedNetworks) + "&notifyAllowedNetworks=" + encodeURIComponent(notifyAllowedNetworks) + "&dnsAppsEnableAutomaticUpdate=" + dnsAppsEnableAutomaticUpdate + "&preferIPv6=" + preferIPv6 + "&udpPayloadSize=" + udpPayloadSize + "&dnssecValidation=" + dnssecValidation
            + "&eDnsClientSubnet=" + eDnsClientSubnet + "&eDnsClientSubnetIPv4PrefixLength=" + eDnsClientSubnetIPv4PrefixLength + "&eDnsClientSubnetIPv6PrefixLength=" + eDnsClientSubnetIPv6PrefixLength + "&eDnsClientSubnetIpv4Override=" + encodeURIComponent(eDnsClientSubnetIpv4Override) + "&eDnsClientSubnetIpv6Override=" + encodeURIComponent(eDnsClientSubnetIpv6Override)
            + "&qpmLimitRequests=" + qpmLimitRequests + "&qpmLimitErrors=" + qpmLimitErrors + "&qpmLimitSampleMinutes=" + qpmLimitSampleMinutes + "&qpmLimitIPv4PrefixLength=" + qpmLimitIPv4PrefixLength + "&qpmLimitIPv6PrefixLength=" + qpmLimitIPv6PrefixLength + "&qpmLimitBypassList=" + encodeURIComponent(qpmLimitBypassList)
            + "&clientTimeout=" + clientTimeout + "&tcpSendTimeout=" + tcpSendTimeout + "&tcpReceiveTimeout=" + tcpReceiveTimeout + "&quicIdleTimeout=" + quicIdleTimeout + "&quicMaxInboundStreams=" + quicMaxInboundStreams + "&listenBacklog=" + listenBacklog + "&maxConcurrentResolutionsPerCore=" + maxConcurrentResolutionsPerCore
            + "&webServiceLocalAddresses=" + encodeURIComponent(webServiceLocalAddresses) + "&webServiceHttpPort=" + webServiceHttpPort + "&webServiceEnableTls=" + webServiceEnableTls + "&webServiceEnableHttp3=" + webServiceEnableHttp3 + "&webServiceHttpToTlsRedirect=" + webServiceHttpToTlsRedirect + "&webServiceUseSelfSignedTlsCertificate=" + webServiceUseSelfSignedTlsCertificate + "&webServiceTlsPort=" + webServiceTlsPort + "&webServiceTlsCertificatePath=" + encodeURIComponent(webServiceTlsCertificatePath) + "&webServiceTlsCertificatePassword=" + encodeURIComponent(webServiceTlsCertificatePassword) + "&webServiceRealIpHeader=" + encodeURIComponent(webServiceRealIpHeader)
            + "&enableDnsOverUdpProxy=" + enableDnsOverUdpProxy + "&enableDnsOverTcpProxy=" + enableDnsOverTcpProxy + "&enableDnsOverHttp=" + enableDnsOverHttp + "&enableDnsOverTls=" + enableDnsOverTls + "&enableDnsOverHttps=" + enableDnsOverHttps + "&enableDnsOverHttp3=" + enableDnsOverHttp3 + "&enableDnsOverQuic=" + enableDnsOverQuic + "&dnsOverUdpProxyPort=" + dnsOverUdpProxyPort + "&dnsOverTcpProxyPort=" + dnsOverTcpProxyPort + "&dnsOverHttpPort=" + dnsOverHttpPort + "&dnsOverTlsPort=" + dnsOverTlsPort + "&dnsOverHttpsPort=" + dnsOverHttpsPort + "&dnsOverQuicPort=" + dnsOverQuicPort + "&reverseProxyNetworkACL=" + encodeURIComponent(reverseProxyNetworkACL) + "&dnsTlsCertificatePath=" + encodeURIComponent(dnsTlsCertificatePath) + "&dnsTlsCertificatePassword=" + encodeURIComponent(dnsTlsCertificatePassword) + "&dnsOverHttpRealIpHeader=" + encodeURIComponent(dnsOverHttpRealIpHeader)
            + "&tsigKeys=" + encodeURIComponent(tsigKeys)
            + "&recursion=" + recursion + "&recursionNetworkACL=" + encodeURIComponent(recursionNetworkACL) + "&randomizeName=" + randomizeName + "&qnameMinimization=" + qnameMinimization + "&nsRevalidation=" + nsRevalidation + "&resolverRetries=" + resolverRetries + "&resolverTimeout=" + resolverTimeout + "&resolverConcurrency=" + resolverConcurrency + "&resolverMaxStackCount=" + resolverMaxStackCount
            + "&saveCache=" + saveCache + "&serveStale=" + serveStale + "&serveStaleTtl=" + serveStaleTtl + "&serveStaleAnswerTtl=" + serveStaleAnswerTtl + "&serveStaleResetTtl=" + serveStaleResetTtl + "&serveStaleMaxWaitTime=" + serveStaleMaxWaitTime + "&cacheMaximumEntries=" + cacheMaximumEntries + "&cacheMinimumRecordTtl=" + cacheMinimumRecordTtl + "&cacheMaximumRecordTtl=" + cacheMaximumRecordTtl + "&cacheNegativeRecordTtl=" + cacheNegativeRecordTtl + "&cacheFailureRecordTtl=" + cacheFailureRecordTtl + "&cachePrefetchEligibility=" + cachePrefetchEligibility + "&cachePrefetchTrigger=" + cachePrefetchTrigger + "&cachePrefetchSampleIntervalInMinutes=" + cachePrefetchSampleIntervalInMinutes + "&cachePrefetchSampleEligibilityHitsPerHour=" + cachePrefetchSampleEligibilityHitsPerHour
            + "&enableBlocking=" + enableBlocking + "&allowTxtBlockingReport=" + allowTxtBlockingReport + "&blockingBypassList=" + encodeURIComponent(blockingBypassList) + "&blockingType=" + blockingType + "&customBlockingAddresses=" + encodeURIComponent(customBlockingAddresses) + "&blockingAnswerTtl=" + blockingAnswerTtl + "&blockListUrls=" + encodeURIComponent(blockListUrls) + "&blockListUpdateIntervalHours=" + blockListUpdateIntervalHours
            + proxy + "&forwarders=" + encodeURIComponent(forwarders) + "&forwarderProtocol=" + forwarderProtocol + "&concurrentForwarding=" + concurrentForwarding + "&forwarderRetries=" + forwarderRetries + "&forwarderTimeout=" + forwarderTimeout + "&forwarderConcurrency=" + forwarderConcurrency
            + "&enableLogging=" + enableLogging + "&ignoreResolverLogs=" + ignoreResolverLogs + "&logQueries=" + logQueries + "&useLocalTime=" + useLocalTime + "&logFolder=" + encodeURIComponent(logFolder) + "&maxLogFileDays=" + maxLogFileDays + "&enableInMemoryStats=" + enableInMemoryStats + "&maxStatFileDays=" + maxStatFileDays,
        processData: false,
        showInnerError: true,
        success: function (responseJSON) {
            loadDnsSettings(responseJSON);

            btn.button('reset');
            showAlert("success", "Settings Saved!", "DNS Server settings were saved successfully.");

            checkForWebConsoleRedirection(responseJSON);
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
            showPageLogin();
        }
    });
}

function addTsigKeyRow(keyName, sharedSecret, algorithmName) {

    var id = Math.floor(Math.random() * 10000);

    var tableHtmlRows = "<tr id=\"tableTsigKeyRow" + id + "\"><td><input type=\"text\" class=\"form-control\" value=\"" + htmlEncode(keyName) + "\"></td>";
    tableHtmlRows += "<td><input type=\"text\" class=\"form-control\" data-optional=\"true\" value=\"" + htmlEncode(sharedSecret) + "\"></td>";

    tableHtmlRows += "<td><select class=\"form-control\">";
    tableHtmlRows += "<option value=\"hmac-md5.sig-alg.reg.int\"" + (algorithmName == "hmac-md5.sig-alg.reg.int" ? " selected" : "") + ">HMAC-MD5 (obsolete)</option>";
    tableHtmlRows += "<option value=\"hmac-sha1\"" + (algorithmName == "hmac-sha1" ? " selected" : "") + ">HMAC-SHA1</option>";
    tableHtmlRows += "<option value=\"hmac-sha256\"" + (algorithmName == "hmac-sha256" ? " selected" : "") + ">HMAC-SHA256 (recommended)</option>";
    tableHtmlRows += "<option value=\"hmac-sha256-128\"" + (algorithmName == "hmac-sha256-128" ? " selected" : "") + ">HMAC-SHA256 (128 bits)</option>";
    tableHtmlRows += "<option value=\"hmac-sha384\"" + (algorithmName == "hmac-sha384" ? " selected" : "") + ">HMAC-SHA384</option>";
    tableHtmlRows += "<option value=\"hmac-sha384-192\"" + (algorithmName == "hmac-sha384-192" ? " selected" : "") + ">HMAC-SHA384 (192 bits)</option>";
    tableHtmlRows += "<option value=\"hmac-sha512\"" + (algorithmName == "hmac-sha512" ? " selected" : "") + ">HMAC-SHA512</option>";
    tableHtmlRows += "<option value=\"hmac-sha512-256\"" + (algorithmName == "hmac-sha512-256" ? " selected" : "") + ">HMAC-SHA512 (256 bits)</option>";
    tableHtmlRows += "</select></td>";

    tableHtmlRows += "<td><button type=\"button\" class=\"btn btn-danger\" onclick=\"$('#tableTsigKeyRow" + id + "').remove();\">Delete</button></td></tr>";

    $("#tableTsigKeys").append(tableHtmlRows);
}

function checkForReverseProxy(responseJSON) {
    if (window.location.protocol == "https:") {
        var currentPort = window.location.port;

        if ((currentPort == 0) || (currentPort == ""))
            currentPort = 443;

        reverseProxyDetected = !responseJSON.response.webServiceEnableTls || (currentPort != responseJSON.response.webServiceTlsPort);
    } else {
        var currentPort = window.location.port;

        if ((currentPort == 0) || (currentPort == ""))
            currentPort = 80;

        reverseProxyDetected = currentPort != responseJSON.response.webServiceHttpPort
    }
}

function checkForWebConsoleRedirection(responseJSON) {
    if (reverseProxyDetected)
        return;

    if (location.protocol == "https:") {
        if (!responseJSON.response.webServiceEnableTls) {
            setTimeout(function () {
                window.open("http://" + window.location.hostname + ":" + responseJSON.response.webServiceHttpPort, "_self");
            }, 2500); //delay redirection to allow web server to restart

            return;
        }

        var currentPort = window.location.port;

        if ((currentPort == 0) || (currentPort == ""))
            currentPort = 443;

        if (currentPort != responseJSON.response.webServiceTlsPort) {
            setTimeout(function () {
                window.open("https://" + window.location.hostname + ":" + responseJSON.response.webServiceTlsPort, "_self");
            }, 2500); //delay redirection to allow web server to restart
        }
    }
    else {
        if (responseJSON.response.webServiceEnableTls && responseJSON.response.webServiceHttpToTlsRedirect) {
            setTimeout(function () {
                window.open("https://" + window.location.hostname + ":" + responseJSON.response.webServiceTlsPort, "_self");
            }, 2500); //delay redirection to allow web server to restart

            return;
        }

        var currentPort = window.location.port;

        if ((currentPort == 0) || (currentPort == ""))
            currentPort = 80;

        if (currentPort != responseJSON.response.webServiceHttpPort) {
            setTimeout(function () {
                window.open("http://" + window.location.hostname + ":" + responseJSON.response.webServiceHttpPort, "_self");
            }, 2500); //delay redirection to allow web server to restart
        }
    }
}

function forceUpdateBlockLists() {
    if (!confirm("Are you sure to force download and update the block lists?"))
        return;

    var btn = $("#btnUpdateBlockListsNow").button('loading');

    HTTPRequest({
        url: "/api/settings/forceUpdateBlockLists?token=" + sessionData.token,
        success: function (responseJSON) {
            btn.button('reset');

            $("#lblBlockListNextUpdatedOn").text("Updating Now");

            showAlert("success", "Updating Block List!", "Block list update was triggered successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
            showPageLogin();
        }
    });
}

function temporaryDisableBlockingNow() {
    var minutes = $("#txtTemporaryDisableBlockingMinutes").val();

    if ((minutes === null) || (minutes === "")) {
        showAlert("warning", "Missing!", "Please enter a value in minutes to temporarily disable blocking.");
        $("#txtTemporaryDisableBlockingMinutes").focus();
        return;
    }

    if (!confirm("Are you sure to temporarily disable blocking for " + minutes + " minute(s)?"))
        return;

    var btn = $("#btnTemporaryDisableBlockingNow").button("loading");

    HTTPRequest({
        url: "/api/settings/temporaryDisableBlocking?token=" + sessionData.token + "&minutes=" + minutes,
        success: function (responseJSON) {
            btn.button("reset");

            $("#chkEnableBlocking").prop("checked", false);
            $("#lblTemporaryDisableBlockingTill").text(moment(responseJSON.response.temporaryDisableBlockingTill).local().format("YYYY-MM-DD HH:mm:ss"));
            updateBlockingState();

            showAlert("success", "Blocking Disabled!", "Blocking was successfully disabled temporarily for " + htmlEncode(minutes) + " minute(s).");

            setTimeout(updateBlockingState, 500);
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
            showPageLogin();
        }
    });
}

function updateBlockingState() {
    var enableBlocking = $("#chkEnableBlocking").prop("checked");

    $("#chkAllowTxtBlockingReport").prop("disabled", !enableBlocking);
    $("#txtTemporaryDisableBlockingMinutes").prop("disabled", !enableBlocking);
    $("#btnTemporaryDisableBlockingNow").prop("disabled", !enableBlocking);
    $("#txtBlockingBypassList").prop("disabled", !enableBlocking);
    $("#rdBlockingTypeAnyAddress").prop("disabled", !enableBlocking);
    $("#rdBlockingTypeNxDomain").prop("disabled", !enableBlocking);
    $("#rdBlockingTypeCustomAddress").prop("disabled", !enableBlocking);
    $("#txtCustomBlockingAddresses").prop("disabled", !enableBlocking || !$("#rdBlockingTypeCustomAddress").prop("checked"));
    $("#txtBlockListUrls").prop("disabled", !enableBlocking);
    $("#optQuickBlockList").prop("disabled", !enableBlocking);
    $("#txtBlockListUpdateIntervalHours").prop("disabled", !enableBlocking);
    $("#btnUpdateBlockListsNow").prop("disabled", !enableBlocking || ($("#txtBlockListUrls").val() == ""));
}

function updateChart(chart, data) {
    chart.data = data;
    chart.update();
    loadChartLegendSettings(chart); //Reload the chart legend
}

function loadChartLegendSettings(chart) {
    var labelFilters = localStorage.getItem("chart_" + chart.id + "_legend");

    if (labelFilters != null) {
        labelFilters = JSON.parse(labelFilters);
        if (chart.config.type == "doughnut" || chart.config.type == "pie") {
            chart.data.labels.forEach((label, index) => {
                let labelFilter = labelFilters.filter(function (f) {
                    return f.title == this.toString();
                }, label);
                if (labelFilter.length > 0) {
                    chart.getDatasetMeta(0).data[index].hidden = labelFilter[0].hidden;
                }
            });
        }
        else {
            chart.data.datasets.forEach((data, index) => {
                let labelFilter = labelFilters.filter(function (f) {
                    return f.title == this.toString();
                }, data.label);
                if (labelFilter.length > 0) {
                    chart.getDatasetMeta(index).hidden = labelFilter[0].hidden;
                }
            });
        }

        chart.update();
    }
}

function saveChartLegendSettings(chart) {
    var labelFilters = [];

    if (chart.config.type == "doughnut" || chart.config.type == "pie") {
        chart.data.labels.forEach((label, index) => {
            var hidden = chart.getDatasetMeta(0).data[index].hidden;
            labelFilters.push(
                {
                    title: label,
                    hidden: hidden
                }
            );
        });
    }
    else {
        chart.data.datasets.forEach((data, index) => {
            var hidden = chart.getDatasetMeta(index).hidden;
            labelFilters.push(
                {
                    title: data.label,
                    hidden: hidden
                }
            );
        });
    }

    localStorage.setItem("chart_" + chart.id + "_legend", JSON.stringify(labelFilters));
}

var chartLegendOnClick = function (e, legendItem) {
    var chartType = this.chart.config.type;

    if (chartType == "doughnut") {
        Chart.defaults.doughnut.legend.onClick.call(this, e, legendItem);
    } else if (chartType == "pie") {
        Chart.defaults.pie.legend.onClick.call(this, e, legendItem);
    } else {
        Chart.defaults.global.legend.onClick.call(this, e, legendItem);
    }

    saveChartLegendSettings(this.chart);
}

function refreshDashboard(hideLoader) {
    if (!$("#mainPanelTabPaneDashboard").hasClass("active"))
        return;

    if (hideLoader == null)
        hideLoader = false;

    var divDashboardLoader = $("#divDashboardLoader");
    var divDashboard = $("#divDashboard");

    var type = $('input[name=rdStatType]:checked').val();
    var custom = "";

    if (type === "custom") {
        var txtStart = $("#dpCustomDayWiseStart").val();
        if (txtStart === null || (txtStart === "")) {
            showAlert("warning", "Missing!", "Please select a start date.");
            $("#dpCustomDayWiseStart").focus();
            return;
        }

        var txtEnd = $("#dpCustomDayWiseEnd").val();
        if (txtEnd === null || (txtEnd === "")) {
            showAlert("warning", "Missing!", "Please select an end date.");
            $("#dpCustomDayWiseEnd").focus();
            return;
        }

        var start = moment(txtStart);
        var end = moment(txtEnd);

        if ((end.diff(start, "days") + 1) > 7) {
            start = moment.utc(txtStart).toISOString();
            end = moment.utc(txtEnd).toISOString();
        }
        else {
            start = start.toISOString();
            end = end.toISOString();
        }

        custom = "&start=" + encodeURIComponent(start) + "&end=" + encodeURIComponent(end);
    }

    if (!hideLoader) {
        divDashboard.hide();
        divDashboardLoader.show();
    }

    HTTPRequest({
        url: "/api/dashboard/stats/get?token=" + sessionData.token + "&type=" + type + "&utc=true" + custom,
        success: function (responseJSON) {

            //stats
            $("#divDashboardStatsTotalQueries").text(responseJSON.response.stats.totalQueries.toLocaleString());
            $("#divDashboardStatsTotalNoError").text(responseJSON.response.stats.totalNoError.toLocaleString());
            $("#divDashboardStatsTotalServerFailure").text(responseJSON.response.stats.totalServerFailure.toLocaleString());
            $("#divDashboardStatsTotalNxDomain").text(responseJSON.response.stats.totalNxDomain.toLocaleString());
            $("#divDashboardStatsTotalRefused").text(responseJSON.response.stats.totalRefused.toLocaleString());

            $("#divDashboardStatsTotalAuthHit").text(responseJSON.response.stats.totalAuthoritative.toLocaleString());
            $("#divDashboardStatsTotalRecursions").text(responseJSON.response.stats.totalRecursive.toLocaleString());
            $("#divDashboardStatsTotalCacheHit").text(responseJSON.response.stats.totalCached.toLocaleString());
            $("#divDashboardStatsTotalBlocked").text(responseJSON.response.stats.totalBlocked.toLocaleString());
            $("#divDashboardStatsTotalDropped").text(responseJSON.response.stats.totalDropped.toLocaleString());

            $("#divDashboardStatsTotalClients").text(responseJSON.response.stats.totalClients.toLocaleString());

            $("#divDashboardStatsZones").text(responseJSON.response.stats.zones.toLocaleString());
            $("#divDashboardStatsCachedEntries").text(responseJSON.response.stats.cachedEntries.toLocaleString());
            $("#divDashboardStatsAllowedZones").text(responseJSON.response.stats.allowedZones.toLocaleString());
            $("#divDashboardStatsBlockedZones").text(responseJSON.response.stats.blockedZones.toLocaleString());
            $("#divDashboardStatsAllowListZones").text(responseJSON.response.stats.allowListZones.toLocaleString());
            $("#divDashboardStatsBlockListZones").text(responseJSON.response.stats.blockListZones.toLocaleString());

            if (responseJSON.response.stats.totalQueries > 0) {
                $("#divDashboardStatsTotalNoErrorPercentage").text((responseJSON.response.stats.totalNoError * 100 / responseJSON.response.stats.totalQueries).toFixed(2) + "%");
                $("#divDashboardStatsTotalServerFailurePercentage").text((responseJSON.response.stats.totalServerFailure * 100 / responseJSON.response.stats.totalQueries).toFixed(2) + "%");
                $("#divDashboardStatsTotalNxDomainPercentage").text((responseJSON.response.stats.totalNxDomain * 100 / responseJSON.response.stats.totalQueries).toFixed(2) + "%");
                $("#divDashboardStatsTotalRefusedPercentage").text((responseJSON.response.stats.totalRefused * 100 / responseJSON.response.stats.totalQueries).toFixed(2) + "%");

                $("#divDashboardStatsTotalAuthHitPercentage").text((responseJSON.response.stats.totalAuthoritative * 100 / responseJSON.response.stats.totalQueries).toFixed(2) + "%");
                $("#divDashboardStatsTotalRecursionsPercentage").text((responseJSON.response.stats.totalRecursive * 100 / responseJSON.response.stats.totalQueries).toFixed(2) + "%");
                $("#divDashboardStatsTotalCacheHitPercentage").text((responseJSON.response.stats.totalCached * 100 / responseJSON.response.stats.totalQueries).toFixed(2) + "%");
                $("#divDashboardStatsTotalBlockedPercentage").text((responseJSON.response.stats.totalBlocked * 100 / responseJSON.response.stats.totalQueries).toFixed(2) + "%");
                $("#divDashboardStatsTotalDroppedPercentage").text((responseJSON.response.stats.totalDropped * 100 / responseJSON.response.stats.totalQueries).toFixed(2) + "%");
            }
            else {
                $("#divDashboardStatsTotalNoErrorPercentage").text("0%");
                $("#divDashboardStatsTotalServerFailurePercentage").text("0%");
                $("#divDashboardStatsTotalNxDomainPercentage").text("0%");
                $("#divDashboardStatsTotalRefusedPercentage").text("0%");

                $("#divDashboardStatsTotalAuthHitPercentage").text("0%");
                $("#divDashboardStatsTotalRecursionsPercentage").text("0%");
                $("#divDashboardStatsTotalCacheHitPercentage").text("0%");
                $("#divDashboardStatsTotalBlockedPercentage").text("0%");
                $("#divDashboardStatsTotalDroppedPercentage").text("0%");
            }

            //main chart

            //fix labels
            switch (responseJSON.response.mainChartData.labelFormat) {
                case "MM/DD":
                case "DD/MM":
                case "MM/YYYY":
                    for (var i = 0; i < responseJSON.response.mainChartData.labels.length; i++) {
                        responseJSON.response.mainChartData.labels[i] = moment(responseJSON.response.mainChartData.labels[i]).utc().format(responseJSON.response.mainChartData.labelFormat);
                    }
                    break;

                default:
                    for (var i = 0; i < responseJSON.response.mainChartData.labels.length; i++) {
                        responseJSON.response.mainChartData.labels[i] = moment(responseJSON.response.mainChartData.labels[i]).local().format(responseJSON.response.mainChartData.labelFormat);
                    }
                    break;
            }

            if (window.chartDashboardMain == null) {
                var contextDashboardMain = document.getElementById("canvasDashboardMain").getContext('2d');

                window.chartDashboardMain = new Chart(contextDashboardMain, {
                    type: 'line',
                    data: responseJSON.response.mainChartData,
                    options: {
                        elements: {
                            line: {
                                tension: 0.2,
                            }
                        },
                        scales: {
                            yAxes: [{
                                ticks: {
                                    beginAtZero: true
                                }
                            }]
                        },
                        legend: {
                            onClick: chartLegendOnClick
                        }
                    }
                });

                loadChartLegendSettings(window.chartDashboardMain);
            }
            else {
                updateChart(window.chartDashboardMain, responseJSON.response.mainChartData);
            }

            //query response chart
            if (window.chartDashboardPie == null) {
                var contextDashboardPie = document.getElementById("canvasDashboardPie").getContext('2d');

                window.chartDashboardPie = new Chart(contextDashboardPie, {
                    type: 'doughnut',
                    data: responseJSON.response.queryResponseChartData,
                    options: {
                        legend: {
                            onClick: chartLegendOnClick
                        }
                    }
                });

                loadChartLegendSettings(window.chartDashboardPie);
            }
            else {
                updateChart(window.chartDashboardPie, responseJSON.response.queryResponseChartData);
            }

            //query type chart
            if (window.chartDashboardPie2 == null) {
                var contextDashboardPie2 = document.getElementById("canvasDashboardPie2").getContext('2d');

                window.chartDashboardPie2 = new Chart(contextDashboardPie2, {
                    type: 'doughnut',
                    data: responseJSON.response.queryTypeChartData,
                    options: {
                        legend: {
                            onClick: chartLegendOnClick
                        }
                    }
                });

                loadChartLegendSettings(window.chartDashboardPie2);
            }
            else {
                updateChart(window.chartDashboardPie2, responseJSON.response.queryTypeChartData);
            }

            //protocol type chart
            if (window.chartDashboardPie3 == null) {
                var contextDashboardPie3 = document.getElementById("canvasDashboardPie3").getContext('2d');

                window.chartDashboardPie3 = new Chart(contextDashboardPie3, {
                    type: 'doughnut',
                    data: responseJSON.response.protocolTypeChartData,
                    options: {
                        legend: {
                            onClick: chartLegendOnClick
                        }
                    }
                });

                loadChartLegendSettings(window.chartDashboardPie3);
            }
            else {
                updateChart(window.chartDashboardPie3, responseJSON.response.protocolTypeChartData);
            }

            //top clients
            {
                var tableHtmlRows;
                var topClients = responseJSON.response.topClients;

                if (topClients.length < 1) {
                    tableHtmlRows = "<tr><td colspan=\"3\" align=\"center\">No Data</td></tr>";
                }
                else {
                    tableHtmlRows = "";

                    for (var i = 0; i < topClients.length; i++) {
                        tableHtmlRows += "<tr" + (topClients[i].rateLimited ? " style=\"color: orange;\"" : "") + "><td style=\"word-wrap: anywhere;\">" + htmlEncode(topClients[i].name) + (topClients[i].rateLimited ? " (rate limited)" : "") + "<br />" + htmlEncode(topClients[i].domain == "" ? "." : topClients[i].domain) + "</td><td>" + topClients[i].hits.toLocaleString();
                        tableHtmlRows += "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnDashboardTopClientsRowOption" + i + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"showQueryLogs(null, '" + topClients[i].name + "'); return false;\">Show Query Logs</a></li>";
                        tableHtmlRows += "</ul></div></td></tr>";
                    }
                }

                $("#tableTopClients").html(tableHtmlRows);
            }

            //top domains
            {
                var tableHtmlRows;
                var topDomains = responseJSON.response.topDomains;

                if (topDomains.length < 1) {
                    tableHtmlRows = "<tr><td colspan=\"3\" align=\"center\">No Data</td></tr>";
                }
                else {
                    tableHtmlRows = "";

                    for (var i = 0; i < topDomains.length; i++) {
                        if (topDomains[i].nameIdn == null)
                            tableHtmlRows += "<tr><td style=\"word-wrap: anywhere;\">" + htmlEncode(topDomains[i].name == "" ? "." : topDomains[i].name) + "</td><td>" + topDomains[i].hits.toLocaleString();
                        else
                            tableHtmlRows += "<tr><td style=\"word-wrap: anywhere;\">" + htmlEncode(topDomains[i].nameIdn) + "</td><td>" + topDomains[i].hits.toLocaleString();

                        tableHtmlRows += "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnDashboardTopDomainsRowOption" + i + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"showQueryLogs('" + topDomains[i].name + "', null); return false;\">Show Query Logs</a></li>";
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"queryDnsServer('" + topDomains[i].name + "'); return false;\">Query DNS Server</a></li>";
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" data-domain=\"" + htmlEncode(topDomains[i].name) + "\" onclick=\"blockDomain(this, 'btnDashboardTopDomainsRowOption'); return false;\">Block Domain</a></li>";
                        tableHtmlRows += "</ul></div></td></tr>";
                    }
                }

                $("#tableTopDomains").html(tableHtmlRows);
            }

            //top blocked domains
            {
                var tableHtmlRows;
                var topBlockedDomains = responseJSON.response.topBlockedDomains;

                if (topBlockedDomains.length < 1) {
                    tableHtmlRows = "<tr><td colspan=\"3\" align=\"center\">No Data</td></tr>";
                }
                else {
                    tableHtmlRows = "";

                    for (var i = 0; i < topBlockedDomains.length; i++) {
                        if (topBlockedDomains[i].nameIdn == null)
                            tableHtmlRows += "<tr><td style=\"word-wrap: anywhere;\">" + htmlEncode(topBlockedDomains[i].name == "" ? "." : topBlockedDomains[i].name) + "</td><td>" + topBlockedDomains[i].hits.toLocaleString();
                        else
                            tableHtmlRows += "<tr><td style=\"word-wrap: anywhere;\">" + htmlEncode(topBlockedDomains[i].nameIdn) + "</td><td>" + topBlockedDomains[i].hits.toLocaleString();

                        tableHtmlRows += "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnDashboardTopBlockedDomainsRowOption" + i + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"showQueryLogs('" + topBlockedDomains[i].name + "', null); return false;\">Show Query Logs</a></li>";
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"queryDnsServer('" + topBlockedDomains[i].name + "'); return false;\">Query DNS Server</a></li>";
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" data-domain=\"" + htmlEncode(topBlockedDomains[i].name) + "\" onclick=\"allowDomain(this, 'btnDashboardTopBlockedDomainsRowOption'); return false;\">Allow Domain</a></li>";
                        tableHtmlRows += "</ul></div></td></tr>";
                    }
                }

                $("#tableTopBlockedDomains").html(tableHtmlRows);
            }

            if (!hideLoader) {
                divDashboardLoader.hide();
                divDashboard.show();
            }
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divDashboardLoader,
        dontHideAlert: hideLoader
    });
}

function showTopStats(statsType, limit) {
    var divTopStatsAlert = $("#divTopStatsAlert");
    var divTopStatsLoader = $("#divTopStatsLoader");

    $("#tableTopStatsClients").hide();
    $("#tableTopStatsDomains").hide();
    $("#tableTopStatsBlockedDomains").hide();
    divTopStatsLoader.show();

    switch (statsType) {
        case "TopClients":
            $("#lblTopStatsTitle").text("Top " + limit + " Clients");
            break;

        case "TopDomains":
            $("#lblTopStatsTitle").text("Top " + limit + " Domains");
            break;

        case "TopBlockedDomains":
            $("#lblTopStatsTitle").text("Top " + limit + " Blocked Domains");
            break;
    }

    $("#modalTopStats").modal("show");

    var type = $('input[name=rdStatType]:checked').val();
    var custom = "";

    if (type === "custom") {
        var txtStart = $("#dpCustomDayWiseStart").val();
        if (txtStart === null || (txtStart === "")) {
            showAlert("warning", "Missing!", "Please select a start date.");
            $("#dpCustomDayWiseStart").focus();
            return;
        }

        var txtEnd = $("#dpCustomDayWiseEnd").val();
        if (txtEnd === null || (txtEnd === "")) {
            showAlert("warning", "Missing!", "Please select an end date.");
            $("#dpCustomDayWiseEnd").focus();
            return;
        }

        var start = moment(txtStart);
        var end = moment(txtEnd);

        if ((end.diff(start, "days") + 1) > 7) {
            start = moment.utc(txtStart).toISOString();
            end = moment.utc(txtEnd).toISOString();
        }
        else {
            start = start.toISOString();
            end = end.toISOString();
        }

        custom = "&start=" + encodeURIComponent(start) + "&end=" + encodeURIComponent(end);
    }

    HTTPRequest({
        url: "/api/dashboard/stats/getTop?token=" + sessionData.token + "&type=" + type + custom + "&statsType=" + statsType + "&limit=" + limit,
        success: function (responseJSON) {
            divTopStatsLoader.hide();

            if (responseJSON.response.topClients != null) {
                var tableHtmlRows;
                var topClients = responseJSON.response.topClients;

                if (topClients.length < 1) {
                    tableHtmlRows = "<tr><td colspan=\"3\" align=\"center\">No Data</td></tr>";
                }
                else {
                    tableHtmlRows = "";

                    for (var i = 0; i < topClients.length; i++) {
                        tableHtmlRows += "<tr" + (topClients[i].rateLimited ? " style=\"color: orange;\"" : "") + "><td style=\"word-wrap: anywhere;\">" + htmlEncode(topClients[i].name) + (topClients[i].rateLimited ? " (rate limited)" : "") + "<br />" + htmlEncode(topClients[i].domain == "" ? "." : topClients[i].domain) + "</td><td>" + topClients[i].hits.toLocaleString();
                        tableHtmlRows += "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnDashboardTopClientsRowOption" + i + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"showQueryLogs(null, '" + topClients[i].name + "'); return false;\">Show Query Logs</a></li>";
                        tableHtmlRows += "</ul></div></td></tr>";
                    }
                }

                $("#tbodyTopStatsClients").html(tableHtmlRows);

                if (topClients.length > 0)
                    $("#tfootTopStatsClients").html("Total Clients: " + topClients.length);
                else
                    $("#tfootTopStatsClients").html("");

                $("#tableTopStatsClients").show();
            }
            else if (responseJSON.response.topDomains != null) {
                var tableHtmlRows;
                var topDomains = responseJSON.response.topDomains;

                if (topDomains.length < 1) {
                    tableHtmlRows = "<tr><td colspan=\"3\" align=\"center\">No Data</td></tr>";
                }
                else {
                    tableHtmlRows = "";

                    for (var i = 0; i < topDomains.length; i++) {
                        if (topDomains[i].nameIdn == null)
                            tableHtmlRows += "<tr><td style=\"word-wrap: anywhere;\">" + htmlEncode(topDomains[i].name == "" ? "." : topDomains[i].name) + "</td><td>" + topDomains[i].hits.toLocaleString();
                        else
                            tableHtmlRows += "<tr><td style=\"word-wrap: anywhere;\">" + htmlEncode(topDomains[i].nameIdn) + "</td><td>" + topDomains[i].hits.toLocaleString();

                        tableHtmlRows += "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnDashboardTopStatsDomainsRowOption" + i + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"showQueryLogs('" + topDomains[i].name + "', null); return false;\">Show Query Logs</a></li>";
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"queryDnsServer('" + topDomains[i].name + "'); return false;\">Query DNS Server</a></li>";
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" data-domain=\"" + htmlEncode(topDomains[i].name) + "\" onclick=\"blockDomain(this, 'btnDashboardTopStatsDomainsRowOption', 'divTopStatsAlert'); return false;\">Block Domain</a></li>";
                        tableHtmlRows += "</ul></div></td></tr>";
                    }
                }

                $("#tbodyTopStatsDomains").html(tableHtmlRows);

                if (topDomains.length > 0)
                    $("#tfootTopStatsDomains").html("Total Domains: " + topDomains.length);
                else
                    $("#tfootTopStatsDomains").html("");

                $("#tableTopStatsDomains").show();
            }
            else if (responseJSON.response.topBlockedDomains != null) {
                var tableHtmlRows;
                var topBlockedDomains = responseJSON.response.topBlockedDomains;

                if (topBlockedDomains.length < 1) {
                    tableHtmlRows = "<tr><td colspan=\"3\" align=\"center\">No Data</td></tr>";
                }
                else {
                    tableHtmlRows = "";

                    for (var i = 0; i < topBlockedDomains.length; i++) {
                        if (topBlockedDomains[i].nameIdn == null)
                            tableHtmlRows += "<tr><td style=\"word-wrap: anywhere;\">" + htmlEncode(topBlockedDomains[i].name == "" ? "." : topBlockedDomains[i].name) + "</td><td>" + topBlockedDomains[i].hits.toLocaleString();
                        else
                            tableHtmlRows += "<tr><td style=\"word-wrap: anywhere;\">" + htmlEncode(topBlockedDomains[i].nameIdn) + "</td><td>" + topBlockedDomains[i].hits.toLocaleString();

                        tableHtmlRows += "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnDashboardTopStatsBlockedDomainsRowOption" + i + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"showQueryLogs('" + topBlockedDomains[i].name + "', null); return false;\">Show Query Logs</a></li>";
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"queryDnsServer('" + topBlockedDomains[i].name + "'); return false;\">Query DNS Server</a></li>";
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" data-domain=\"" + htmlEncode(topBlockedDomains[i].name) + "\" onclick=\"allowDomain(this, 'btnDashboardTopStatsBlockedDomainsRowOption', 'divTopStatsAlert'); return false;\">Allow Domain</a></li>";
                        tableHtmlRows += "</ul></div></td></tr>";
                    }
                }

                $("#tbodyTopStatsBlockedDomains").html(tableHtmlRows);

                if (topBlockedDomains.length > 0)
                    $("#tfootTopStatsBlockedDomains").html("Total Domains: " + topBlockedDomains.length);
                else
                    $("#tfootTopStatsBlockedDomains").html("");

                $("#tableTopStatsBlockedDomains").show();
            }

            $("#divTopStatsData").animate({ scrollTop: 0 }, "fast");
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divTopStatsLoader,
        objAlertPlaceholder: divTopStatsAlert
    });
}

function resolveQuery(importRecords) {
    if (importRecords == null)
        importRecords = false;

    var server = $("#txtDnsClientNameServer").val();

    if ((server.indexOf("recursive-resolver") !== -1) || (server.indexOf("system-dns") !== -1))
        $("#optDnsClientProtocol").val("UDP");

    var domain = $("#txtDnsClientDomain").val();
    var type = $("#optDnsClientType").val();
    var protocol = $("#optDnsClientProtocol").val();
    var dnssecValidation = $("#chkDnsClientDnssecValidation").prop("checked");
    var eDnsClientSubnet = $("#txtDnsClientEDnsClientSubnet").val();

    {
        var i = server.indexOf("{");
        if (i > -1) {
            var j = server.lastIndexOf("}");
            server = server.substring(i + 1, j);
        }
    }

    server = server.trim();

    if ((server === null) || (server === "")) {
        showAlert("warning", "Missing!", "Please enter a valid Name Server.");
        $("#txtDnsClientNameServer").focus();
        return;
    }

    if ((domain === null) || (domain === "")) {
        showAlert("warning", "Missing!", "Please enter a domain name to query.");
        $("#txtDnsClientDomain").focus();
        return;
    }

    {
        var i = domain.indexOf("://");
        if (i > -1) {
            var j = domain.indexOf(":", i + 3);

            if (j < 0)
                j = domain.indexOf("/", i + 3);

            if (j > -1)
                domain = domain.substring(i + 3, j);
            else
                domain = domain.substring(i + 3);

            $("#txtDnsClientDomain").val(domain);
        }
    }

    if (importRecords) {
        if (!confirm("Importing all the records from the response of this query will add them into an existing primary or conditional forwarder zone. If a matching zone does not exists, a new primary zone for '" + domain + "' will be created.\n\nAre you sure you want to import all records?"))
            return;
    }

    var btn = $(importRecords ? "#btnDnsClientImport" : "#btnDnsClientResolve").button("loading");
    var btnOther = $(importRecords ? "#btnDnsClientResolve" : "#btnDnsClientImport").prop("disabled", true);

    var divDnsClientLoader = $("#divDnsClientLoader");
    var divDnsClientOutputAccordion = $("#divDnsClientOutputAccordion");

    divDnsClientOutputAccordion.hide();
    divDnsClientLoader.show();

    HTTPRequest({
        url: "/api/dnsClient/resolve?token=" + sessionData.token + "&server=" + encodeURIComponent(server) + "&domain=" + encodeURIComponent(domain) + "&type=" + type + "&protocol=" + protocol + "&dnssec=" + dnssecValidation + "&eDnsClientSubnet=" + encodeURIComponent(eDnsClientSubnet) + (importRecords ? "&import=true" : ""),
        success: function (responseJSON) {
            divDnsClientLoader.hide();
            btn.button("reset");
            btnOther.prop("disabled", false);

            $("#preDnsClientFinalResponse").text(JSON.stringify(responseJSON.response.result, null, 2));
            $("#divDnsClientFinalResponseCollapse").collapse("show");
            $("#divDnsClientRawResponsesCollapse").collapse("hide");
            divDnsClientOutputAccordion.show();

            if ((responseJSON.response.rawResponses != null)) {
                if (responseJSON.response.rawResponses.length == 0) {
                    $("#divDnsClientRawResponsePanel").hide();
                }
                else {
                    var rawListHtml = "";

                    for (var i = 0; i < responseJSON.response.rawResponses.length; i++) {
                        rawListHtml += "<li class=\"list-group-item\"><pre style=\"margin-top: 5px; margin-bottom: 5px;\">" + JSON.stringify(responseJSON.response.rawResponses[i], null, 2) + "</pre></li>";
                    }

                    $("#spanDnsClientRawResponsesCount").text(responseJSON.response.rawResponses.length);
                    $("#ulDnsClientRawResponsesList").html(rawListHtml);
                    $("#divDnsClientRawResponsesCollapse").collapse("hide");
                    $("#divDnsClientRawResponsePanel").show();
                }
            }

            if (responseJSON.response.warningMessage != null) {
                showAlert("warning", "Warning!", responseJSON.response.warningMessage);
            }
            else if (importRecords) {
                showAlert("success", "Records Imported!", "Resource records resolved by this DNS client query were successfully imported into this server.");
            }
        },
        error: function () {
            divDnsClientLoader.hide();
            btn.button('reset');
            btnOther.prop("disabled", false);
        },
        invalidToken: function () {
            divDnsClientLoader.hide();
            btn.button('reset');
            btnOther.prop("disabled", false);
            showPageLogin();
        },
        objLoaderPlaceholder: divDnsClientLoader,
        showInnerError: true
    });

    //add server name to list if doesnt exists
    var txtServerName = $("#txtDnsClientNameServer").val();
    var containsServer = false;

    $("#optDnsClientNameServers a").each(function () {
        if ($(this).html() === txtServerName)
            containsServer = true;
    });

    if (!containsServer)
        $("#optDnsClientNameServers").prepend('<li><a href="#">' + htmlEncode(txtServerName) + '</a></li>');
}

function queryDnsServer(domain, type) {
    if (type == null)
        type = "A";

    $("#txtDnsClientNameServer").val("This Server {this-server}");
    $("#txtDnsClientDomain").val(domain);
    $("#optDnsClientType").val(type);
    $("#optDnsClientProtocol").val("UDP");
    $("#txtDnsClientEDnsClientSubnet").val("");
    $("#chkDnsClientDnssecValidation").prop("checked", false);

    $("#mainPanelTabListDashboard").removeClass("active");
    $("#mainPanelTabPaneDashboard").removeClass("active");

    $("#mainPanelTabListLogs").removeClass("active");
    $("#mainPanelTabPaneLogs").removeClass("active");

    $("#mainPanelTabListDnsClient").addClass("active");
    $("#mainPanelTabPaneDnsClient").addClass("active");

    $("#modalTopStats").modal("hide");

    resolveQuery();
}

function resetBackupSettingsModal() {
    $("#divBackupSettingsAlert").html("");

    $("#chkBackupAuthConfig").prop("checked", true);
    $("#chkBackupDnsSettings").prop("checked", true);
    $("#chkBackupLogSettings").prop("checked", true);
    $("#chkBackupZones").prop("checked", true);
    $("#chkBackupAllowedZones").prop("checked", true);
    $("#chkBackupBlockedZones").prop("checked", true);
    $("#chkBackupScopes").prop("checked", true);
    $("#chkBackupApps").prop("checked", true);
    $("#chkBackupStats").prop("checked", true);
    $("#chkBackupLogs").prop("checked", false);
    $("#chkBackupBlockLists").prop("checked", true);
}

function backupSettings() {
    var divBackupSettingsAlert = $("#divBackupSettingsAlert");

    var blockLists = $("#chkBackupBlockLists").prop('checked');
    var logs = $("#chkBackupLogs").prop('checked');
    var scopes = $("#chkBackupScopes").prop('checked');
    var apps = $("#chkBackupApps").prop('checked');
    var stats = $("#chkBackupStats").prop('checked');
    var zones = $("#chkBackupZones").prop('checked');
    var allowedZones = $("#chkBackupAllowedZones").prop('checked');
    var blockedZones = $("#chkBackupBlockedZones").prop('checked');
    var dnsSettings = $("#chkBackupDnsSettings").prop('checked');
    var authConfig = $("#chkBackupAuthConfig").prop('checked');
    var logSettings = $("#chkBackupLogSettings").prop('checked');

    if (!blockLists && !logs && !scopes && !apps && !stats && !zones && !allowedZones && !blockedZones && !dnsSettings && !authConfig && !logSettings) {
        showAlert("warning", "Missing!", "Please select at least one item to backup.", divBackupSettingsAlert);
        return;
    }

    window.open("/api/settings/backup?token=" + sessionData.token + "&blockLists=" + blockLists + "&logs=" + logs + "&scopes=" + scopes + "&apps=" + apps + "&stats=" + stats + "&zones=" + zones + "&allowedZones=" + allowedZones + "&blockedZones=" + blockedZones + "&dnsSettings=" + dnsSettings + "&authConfig=" + authConfig + "&logSettings=" + logSettings + "&ts=" + (new Date().getTime()), "_blank");

    $("#modalBackupSettings").modal("hide");
    showAlert("success", "Backed Up!", "Settings were backed up successfully.");
}

function resetRestoreSettingsModal() {
    $("#divRestoreSettingsAlert").html("");

    $("#fileBackupZip").val("");

    $("#chkRestoreAuthConfig").prop("checked", true);
    $("#chkRestoreDnsSettings").prop("checked", true);
    $("#chkRestoreLogSettings").prop("checked", true);
    $("#chkRestoreZones").prop("checked", true);
    $("#chkRestoreAllowedZones").prop("checked", true);
    $("#chkRestoreBlockedZones").prop("checked", true);
    $("#chkRestoreScopes").prop("checked", true);
    $("#chkRestoreApps").prop("checked", true);
    $("#chkRestoreStats").prop("checked", true);
    $("#chkRestoreLogs").prop("checked", false);
    $("#chkRestoreBlockLists").prop("checked", true);
    $("#chkDeleteExistingFiles").prop("checked", true);
}

function restoreSettings() {
    var divRestoreSettingsAlert = $("#divRestoreSettingsAlert");

    var fileBackupZip = $("#fileBackupZip");

    if (fileBackupZip[0].files.length === 0) {
        showAlert("warning", "Missing!", "Please select a backup zip file to restore.", divRestoreSettingsAlert);
        fileBackupZip.focus();
        return;
    }

    var blockLists = $("#chkRestoreBlockLists").prop('checked');
    var logs = $("#chkRestoreLogs").prop('checked');
    var scopes = $("#chkRestoreScopes").prop('checked');
    var apps = $("#chkRestoreApps").prop('checked');
    var stats = $("#chkRestoreStats").prop('checked');
    var zones = $("#chkRestoreZones").prop('checked');
    var allowedZones = $("#chkRestoreAllowedZones").prop('checked');
    var blockedZones = $("#chkRestoreBlockedZones").prop('checked');
    var dnsSettings = $("#chkRestoreDnsSettings").prop('checked');
    var authConfig = $("#chkRestoreAuthConfig").prop('checked');
    var logSettings = $("#chkRestoreLogSettings").prop('checked');

    var deleteExistingFiles = $("#chkDeleteExistingFiles").prop('checked');

    if (!blockLists && !logs && !scopes && !apps && !stats && !zones && !allowedZones && !blockedZones && !dnsSettings && !authConfig && !logSettings) {
        showAlert("warning", "Missing!", "Please select at least one item to restore.", divRestoreSettingsAlert);
        return;
    }

    var formData = new FormData();
    formData.append("fileBackupZip", $("#fileBackupZip")[0].files[0]);

    var btn = $("#btnRestoreSettings").button('loading');

    HTTPRequest({
        url: "/api/settings/restore?token=" + sessionData.token + "&blockLists=" + blockLists + "&logs=" + logs + "&scopes=" + scopes + "&apps=" + apps + "&stats=" + stats + "&zones=" + zones + "&allowedZones=" + allowedZones + "&blockedZones=" + blockedZones + "&dnsSettings=" + dnsSettings + "&authConfig=" + authConfig + "&logSettings=" + logSettings + "&deleteExistingFiles=" + deleteExistingFiles,
        method: "POST",
        data: formData,
        contentType: false,
        processData: false,
        success: function (responseJSON) {
            loadDnsSettings(responseJSON);

            $("#modalRestoreSettings").modal("hide");
            btn.button('reset');

            showAlert("success", "Restored!", "Settings were restored successfully.");

            checkForWebConsoleRedirection(responseJSON);
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
            showPageLogin();
        },
        objAlertPlaceholder: divRestoreSettingsAlert
    });
}
