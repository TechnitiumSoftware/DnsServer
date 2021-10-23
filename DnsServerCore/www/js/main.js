/*
Technitium DNS Server
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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

var token = null;
var refreshTimerHandle;
var reverseProxyDetected = false;

function showPageLogin() {
    hideAlert();

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

function showPageMain(username) {
    hideAlert();

    $("#pageLogin").hide();

    $("#mnuUserDisplayName").text(username);
    $("#txtChangePasswordUsername").val(username);
    $("#mnuUser").show();

    $(".nav-tabs li").removeClass("active");
    $(".tab-pane").removeClass("active");
    $("#mainPanelTabListDashboard").addClass("active");
    $("#mainPanelTabPaneDashboard").addClass("active");
    $("#settingsTabListGeneral").addClass("active");
    $("#settingsTabPaneGeneral").addClass("active");
    $("#dhcpTabListLeases").addClass("active");
    $("#dhcpTabPaneLeases").addClass("active");
    $("#logsTabListLogViewer").addClass("active");
    $("#logsTabPaneLogViewer").addClass("active");
    $("#divDhcpViewScopes").show();
    $("#divDhcpEditScope").hide();

    $("#divViewZones").show();
    $("#divEditZone").hide();

    $("#txtDnsClientNameServer").val("This Server {this-server}");
    $("#txtDnsClientDomain").val("");
    $("#optDnsClientType").val("A");
    $("#optDnsClientProtocol").val("UDP");
    $("#divDnsClientLoader").hide();
    $("#divDnsClientOutput").text("");
    $("#preDnsClientOutput").hide();

    $("#divLogViewer").hide();

    $("#pageMain").show();

    loadDnsSettings();
    refreshDashboard();
    refreshCachedZonesList();
    refreshAllowedZonesList();
    refreshBlockedZonesList();
    checkForUpdate();

    refreshTimerHandle = setInterval(function () {
        var type = $('input[name=rdStatType]:checked').val();
        if (type === "lastHour")
            refreshDashboard(true);
    }, 60000);
}

$(function () {
    var headerHtml = $("#header").html();

    $("#header").html("<div class=\"title\"><a href=\"/\"><img src=\"/img/logo25x25.png\" alt=\"Technitium Logo\" /><span class=\"text\" style=\"color: #ffffff;\">Technitium</span></a>" + headerHtml + "</div>");
    $("#footer").html("<div class=\"content\"><a href=\"https://technitium.com/\" target=\"_blank\">Technitium</a> | <a href=\"https://blog.technitium.com/\" target=\"_blank\">Blog</a> | <a href=\"https://go.technitium.com/?id=35\" target=\"_blank\">Donate</a> | <a href=\"https://dnsclient.net/\" target=\"_blank\">DNS Client</a> | <a href=\"https://github.com/TechnitiumSoftware/DnsServer\" target=\"_blank\"><i class=\"fa fa-github\"></i>&nbsp;GitHub</a> | <a href=\"https://technitium.com/aboutus.html\" target=\"_blank\">About</a></div>");

    //dropdown list box support
    $('.dropdown').on('click', 'a', function (e) {
        e.preventDefault();

        var itemText = $(this).text();
        $(this).closest('.dropdown').find('input').val(itemText);

        if ((itemText.indexOf("TLS") !== -1) || (itemText.indexOf(":853") !== -1))
            $("#optDnsClientProtocol").val("TLS");
        else if (itemText.indexOf("HTTPS-JSON") !== -1)
            $("#optDnsClientProtocol").val("HttpsJson");
        else if ((itemText.indexOf("HTTPS") !== -1) || (itemText.indexOf("http://") !== -1) || (itemText.indexOf("https://") !== -1))
            $("#optDnsClientProtocol").val("Https");
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
        if (recursion === "UseSpecifiedNetworks") {
            $("#txtRecursionDeniedNetworks").prop("disabled", false);
            $("#txtRecursionAllowedNetworks").prop("disabled", false);
        }
        else {
            $("#txtRecursionDeniedNetworks").prop("disabled", true);
            $("#txtRecursionAllowedNetworks").prop("disabled", true);
        }
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
        $("#chkWebServiceHttpToTlsRedirect").prop("disabled", !webServiceEnableTls);
        $("#chkWebServiceUseSelfSignedTlsCertificate").prop("disabled", !webServiceEnableTls);
        $("#txtWebServiceTlsPort").prop("disabled", !webServiceEnableTls);
        $("#txtWebServiceTlsCertificatePath").prop("disabled", !webServiceEnableTls);
        $("#txtWebServiceTlsCertificatePassword").prop("disabled", !webServiceEnableTls);
    });

    $("#chkEnableDnsOverTls").click(function () {
        var enableDnsOverTls = $("#chkEnableDnsOverTls").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");

        $("#txtDnsTlsCertificatePath").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps);
        $("#txtDnsTlsCertificatePassword").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps);
    });

    $("#chkEnableDnsOverHttps").click(function () {
        var enableDnsOverTls = $("#chkEnableDnsOverTls").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");

        $("#txtDnsTlsCertificatePath").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps);
        $("#txtDnsTlsCertificatePassword").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps);
    });

    $("#chkEnableLogging").click(function () {
        var enableLogging = $("#chkEnableLogging").prop("checked");
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

                defaultList += "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" + "\n";
                defaultList += "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt" + "\n";
                defaultList += "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt" + "\n";

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

            case "cloudflare-json":
                $("#txtForwarders").val("https://cloudflare-dns.com/dns-query (1.1.1.1)\r\nhttps://cloudflare-dns.com/dns-query (1.0.0.1)");
                $("#rdForwarderProtocolHttpsJson").prop("checked", true);
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

            case "google-json":
                $("#txtForwarders").val("https://dns.google/dns-query (8.8.8.8)\r\nhttps://dns.google/dns-query (8.8.4.4)");
                $("#rdForwarderProtocolHttpsJson").prop("checked", true);
                break;


            case "quad9-udp":
                $("#txtForwarders").val("9.9.9.9");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;

            case "quad9-udp-ipv6":
                $("#txtForwarders").val("[2620:fe::fe]");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;

            case "quad9-tcp":
                $("#txtForwarders").val("9.9.9.9");
                $("#rdForwarderProtocolTcp").prop("checked", true);
                break;

            case "quad9-tcp-ipv6":
                $("#txtForwarders").val("[2620:fe::fe]");
                $("#rdForwarderProtocolTcp").prop("checked", true);
                break;

            case "quad9-tls":
                $("#txtForwarders").val("dns.quad9.net (9.9.9.9:853)");
                $("#rdForwarderProtocolTls").prop("checked", true);
                break;

            case "quad9-tls-ipv6":
                $("#txtForwarders").val("dns.quad9.net ([2620:fe::fe]:853)");
                $("#rdForwarderProtocolTls").prop("checked", true);
                break;

            case "quad9-https":
                $("#txtForwarders").val("https://dns.quad9.net/dns-query (9.9.9.9)");
                $("#rdForwarderProtocolHttps").prop("checked", true);
                break;


            case "quad9-unsecure-udp":
                $("#txtForwarders").val("9.9.9.10");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;

            case "quad9-unsecure-udp-ipv6":
                $("#txtForwarders").val("[2620:fe::10]");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;

            case "quad9-unsecure-tcp":
                $("#txtForwarders").val("9.9.9.10");
                $("#rdForwarderProtocolTcp").prop("checked", true);
                break;

            case "quad9-unsecure-tcp-ipv6":
                $("#txtForwarders").val("[2620:fe::10]");
                $("#rdForwarderProtocolTcp").prop("checked", true);
                break;

            case "quad9-unsecure-tls":
                $("#txtForwarders").val("dns10.quad9.net (9.9.9.10:853)");
                $("#rdForwarderProtocolTls").prop("checked", true);
                break;

            case "quad9-unsecure-tls-ipv6":
                $("#txtForwarders").val("dns10.quad9.net ([2620:fe::10]:853)");
                $("#rdForwarderProtocolTls").prop("checked", true);
                break;

            case "quad9-unsecure-https":
                $("#txtForwarders").val("https://dns10.quad9.net/dns-query (9.9.9.10)");
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


            case "opendns-fs-udp":
                $("#txtForwarders").val("208.67.222.123\r\n208.67.220.123");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;


            case "none":
                $("#txtForwarders").val("");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;
        }
    });

    $("#dpCustomDayWiseStart").datepicker();
    $("#dpCustomDayWiseStart").datepicker("option", "dateFormat", "yy-m-d");

    $("#dpCustomDayWiseEnd").datepicker();
    $("#dpCustomDayWiseEnd").datepicker("option", "dateFormat", "yy-m-d");

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

    $("#lblDoHHost").text(window.location.hostname + ":8053");

    showPageLogin();
    login("admin", "admin");
});

function login(username, password) {
    var autoLogin = false;

    if (username == null) {
        username = $("#txtUser").val().toLowerCase();
        password = $("#txtPass").val();
    }
    else {
        autoLogin = true;
    }

    if ((username === null) || (username === "")) {
        showAlert("warning", "Missing!", "Please enter an username.");
        $("#txtUser").focus();
        return;
    }

    if ((password === null) || (password === "")) {
        showAlert("warning", "Missing!", "Please enter a password.");
        $("#txtPass").focus();
        return;
    }

    var btn = $("#btnLogin").button('loading');

    HTTPRequest({
        url: "/api/login?user=" + encodeURIComponent(username) + "&pass=" + encodeURIComponent(password),
        success: function (responseJSON) {
            token = responseJSON.token;

            showPageMain(username);

            if ((username === "admin") && (password === "admin")) {
                $('#modalChangePassword').modal();

                setTimeout(function () {
                    $("#txtChangePasswordNewPassword").focus();
                }, 1000);
            }
        },
        error: function () {
            btn.button('reset');
            $("#txtUser").focus();

            if (autoLogin)
                hideAlert();
        }
    });
}

function logout() {
    HTTPRequest({
        url: "/api/logout?token=" + token,
        success: function (responseJSON) {
            token = null;
            showPageLogin();
        },
        error: function () {
            token = null;
            showPageLogin();
        }
    });
}

function resetChangePasswordModal() {
    $("#divChangePasswordAlert").html("");
    $("#txtChangePasswordNewPassword").val("");
    $("#txtChangePasswordConfirmPassword").val("");

    setTimeout(function () {
        $("#txtChangePasswordNewPassword").focus();
    }, 1000);
}

function changePassword() {
    var divChangePasswordAlert = $("#divChangePasswordAlert");
    var newPassword = $("#txtChangePasswordNewPassword").val();
    var confirmPassword = $("#txtChangePasswordConfirmPassword").val();

    if ((newPassword === null) || (newPassword === "")) {
        showAlert("warning", "Missing!", "Please enter new password.", divChangePasswordAlert);
        $("#txtChangePasswordNewPassword").focus();
        return;
    }

    if ((confirmPassword === null) || (confirmPassword === "")) {
        showAlert("warning", "Missing!", "Please enter confirm password.", divChangePasswordAlert);
        $("#txtChangePasswordConfirmPassword").focus();
        return;
    }

    if (newPassword !== confirmPassword) {
        showAlert("warning", "Mismatch!", "Passwords do not match. Please try again.", divChangePasswordAlert);
        $("#txtChangePasswordNewPassword").focus();
        return;
    }

    var btn = $("#btnChangePasswordSave").button('loading');

    HTTPRequest({
        url: "/api/changePassword?token=" + token + "&pass=" + encodeURIComponent(newPassword),
        success: function (responseJSON) {
            $("#modalChangePassword").modal("hide");
            btn.button('reset');

            showAlert("success", "Password Changed!", "Password was changed successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
            showPageLogin();
        },
        objAlertPlaceholder: divChangePasswordAlert
    });
}

function checkForUpdate() {
    HTTPRequest({
        url: "/api/checkForUpdate?token=" + token,
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

function loadDnsSettings() {
    var divDnsSettingsLoader = $("#divDnsSettingsLoader");
    var divDnsSettings = $("#divDnsSettings");

    divDnsSettings.hide();
    divDnsSettingsLoader.show();

    HTTPRequest({
        url: "/api/getDnsSettings?token=" + token,
        success: function (responseJSON) {
            document.title = responseJSON.response.dnsServerDomain + " - " + "Technitium DNS Server v" + responseJSON.response.version;
            $("#lblAboutVersion").text(responseJSON.response.version);
            checkForReverseProxy(responseJSON);

            $("#txtDnsServerDomain").val(responseJSON.response.dnsServerDomain);
            $("#lblDnsServerDomain").text(" - " + responseJSON.response.dnsServerDomain);

            var dnsServerLocalEndPoints = responseJSON.response.dnsServerLocalEndPoints;
            if (dnsServerLocalEndPoints == null) {
                $("#txtDnsServerLocalEndPoints").val("0.0.0.0:53\r\n[::]:53");
            }
            else {
                var value = "";

                for (var i = 0; i < dnsServerLocalEndPoints.length; i++)
                    value += dnsServerLocalEndPoints[i] + "\r\n";

                $("#txtDnsServerLocalEndPoints").val(value);
            }

            var webServiceLocalAddresses = responseJSON.response.webServiceLocalAddresses;
            if (webServiceLocalAddresses == null) {
                $("#txtWebServiceLocalAddresses").val("0.0.0.0\r\n[::]");
            }
            else {
                var value = "";

                for (var i = 0; i < webServiceLocalAddresses.length; i++)
                    value += webServiceLocalAddresses[i] + "\r\n";

                $("#txtWebServiceLocalAddresses").val(value);
            }

            $("#txtWebServiceHttpPort").val(responseJSON.response.webServiceHttpPort);

            $("#chkWebServiceEnableTls").prop("checked", responseJSON.response.webServiceEnableTls);
            $("#chkWebServiceHttpToTlsRedirect").prop("disabled", !responseJSON.response.webServiceEnableTls);
            $("#chkWebServiceUseSelfSignedTlsCertificate").prop("disabled", !responseJSON.response.webServiceEnableTls);
            $("#txtWebServiceTlsPort").prop("disabled", !responseJSON.response.webServiceEnableTls);
            $("#txtWebServiceTlsCertificatePath").prop("disabled", !responseJSON.response.webServiceEnableTls);
            $("#txtWebServiceTlsCertificatePassword").prop("disabled", !responseJSON.response.webServiceEnableTls);

            $("#chkWebServiceHttpToTlsRedirect").prop("checked", responseJSON.response.webServiceHttpToTlsRedirect);
            $("#chkWebServiceUseSelfSignedTlsCertificate").prop("checked", responseJSON.response.webServiceUseSelfSignedTlsCertificate);
            $("#txtWebServiceTlsPort").val(responseJSON.response.webServiceTlsPort);
            $("#txtWebServiceTlsCertificatePath").val(responseJSON.response.webServiceTlsCertificatePath);

            if (responseJSON.response.webServiceTlsCertificatePath == null)
                $("#txtWebServiceTlsCertificatePassword").val("");
            else
                $("#txtWebServiceTlsCertificatePassword").val(responseJSON.response.webServiceTlsCertificatePassword);

            $("#chkEnableDnsOverHttp").prop("checked", responseJSON.response.enableDnsOverHttp);
            $("#chkEnableDnsOverTls").prop("checked", responseJSON.response.enableDnsOverTls);
            $("#chkEnableDnsOverHttps").prop("checked", responseJSON.response.enableDnsOverHttps);

            $("#txtDnsTlsCertificatePath").prop("disabled", !responseJSON.response.enableDnsOverTls && !responseJSON.response.enableDnsOverHttps);
            $("#txtDnsTlsCertificatePassword").prop("disabled", !responseJSON.response.enableDnsOverTls && !responseJSON.response.enableDnsOverHttps);

            $("#txtDnsTlsCertificatePath").val(responseJSON.response.dnsTlsCertificatePath);

            if (responseJSON.response.dnsTlsCertificatePath == null)
                $("#txtDnsTlsCertificatePassword").val("");
            else
                $("#txtDnsTlsCertificatePassword").val(responseJSON.response.dnsTlsCertificatePassword);

            $("#tableTsigKeys").html("");

            if (responseJSON.response.tsigKeys != null) {
                for (var i = 0; i < responseJSON.response.tsigKeys.length; i++) {
                    addTsigKeyRow(responseJSON.response.tsigKeys[i].keyName, responseJSON.response.tsigKeys[i].sharedSecret, responseJSON.response.tsigKeys[i].algorithmName);
                }

                updateTsigKeyNamesDropdowns(responseJSON.response.tsigKeys);
            }

            $("#txtDefaultRecordTtl").val(responseJSON.response.defaultRecordTtl);
            $("#txtAddEditRecordTtl").attr("placeholder", responseJSON.response.defaultRecordTtl);

            $("#chkPreferIPv6").prop("checked", responseJSON.response.preferIPv6);

            $("#chkEnableLogging").prop("checked", responseJSON.response.enableLogging);
            $("#chkLogQueries").prop("disabled", !responseJSON.response.enableLogging);
            $("#chkUseLocalTime").prop("disabled", !responseJSON.response.enableLogging);
            $("#txtLogFolderPath").prop("disabled", !responseJSON.response.enableLogging);
            $("#chkLogQueries").prop("checked", responseJSON.response.logQueries);
            $("#chkUseLocalTime").prop("checked", responseJSON.response.useLocalTime);
            $("#txtLogFolderPath").val(responseJSON.response.logFolder);
            $("#txtMaxLogFileDays").val(responseJSON.response.maxLogFileDays);
            $("#txtMaxStatFileDays").val(responseJSON.response.maxStatFileDays);

            $("#txtRecursionDeniedNetworks").prop("disabled", true);
            $("#txtRecursionAllowedNetworks").prop("disabled", true);

            switch (responseJSON.response.recursion) {
                case "Allow":
                    $("#rdRecursionAllow").prop("checked", true);
                    break;

                case "AllowOnlyForPrivateNetworks":
                    $("#rdRecursionAllowOnlyForPrivateNetworks").prop("checked", true);
                    break;

                case "UseSpecifiedNetworks":
                    $("#rdRecursionUseSpecifiedNetworks").prop("checked", true);
                    $("#txtRecursionDeniedNetworks").prop("disabled", false);
                    $("#txtRecursionAllowedNetworks").prop("disabled", false);
                    break;

                case "Deny":
                default:
                    $("#rdRecursionDeny").prop("checked", true);
                    break;
            }

            {
                var value = "";

                for (var i = 0; i < responseJSON.response.recursionDeniedNetworks.length; i++)
                    value += responseJSON.response.recursionDeniedNetworks[i] + "\r\n";

                $("#txtRecursionDeniedNetworks").val(value);
            }

            {
                var value = "";

                for (var i = 0; i < responseJSON.response.recursionAllowedNetworks.length; i++)
                    value += responseJSON.response.recursionAllowedNetworks[i] + "\r\n";

                $("#txtRecursionAllowedNetworks").val(value);
            }

            $("#chkRandomizeName").prop("checked", responseJSON.response.randomizeName);
            $("#chkQnameMinimization").prop("checked", responseJSON.response.qnameMinimization);
            $("#chkNsRevalidation").prop("checked", responseJSON.response.nsRevalidation);

            $("#txtQpmLimitRequests").val(responseJSON.response.qpmLimitRequests);
            $("#txtQpmLimitErrors").val(responseJSON.response.qpmLimitErrors);
            $("#txtQpmLimitSampleMinutes").val(responseJSON.response.qpmLimitSampleMinutes);
            $("#txtQpmLimitIPv4PrefixLength").val(responseJSON.response.qpmLimitIPv4PrefixLength);
            $("#txtQpmLimitIPv6PrefixLength").val(responseJSON.response.qpmLimitIPv6PrefixLength);

            $("#chkServeStale").prop("checked", responseJSON.response.serveStale);
            $("#txtServeStaleTtl").prop("disabled", !responseJSON.response.serveStale);
            $("#txtServeStaleTtl").val(responseJSON.response.serveStaleTtl);

            $("#txtCacheMinimumRecordTtl").val(responseJSON.response.cacheMinimumRecordTtl);
            $("#txtCacheMaximumRecordTtl").val(responseJSON.response.cacheMaximumRecordTtl);
            $("#txtCacheNegativeRecordTtl").val(responseJSON.response.cacheNegativeRecordTtl);
            $("#txtCacheFailureRecordTtl").val(responseJSON.response.cacheFailureRecordTtl);

            $("#txtCachePrefetchEligibility").val(responseJSON.response.cachePrefetchEligibility);
            $("#txtCachePrefetchTrigger").val(responseJSON.response.cachePrefetchTrigger);
            $("#txtCachePrefetchSampleIntervalInMinutes").val(responseJSON.response.cachePrefetchSampleIntervalInMinutes);
            $("#txtCachePrefetchSampleEligibilityHitsPerHour").val(responseJSON.response.cachePrefetchSampleEligibilityHitsPerHour);

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

                {
                    var value = "";

                    for (var i = 0; i < proxy.bypass.length; i++)
                        value += proxy.bypass[i] + "\r\n";

                    $("#txtProxyBypassList").val(value);
                }

                $("#txtProxyAddress").prop("disabled", false);
                $("#txtProxyPort").prop("disabled", false);
                $("#txtProxyUsername").prop("disabled", false);
                $("#txtProxyPassword").prop("disabled", false);
                $("#txtProxyBypassList").prop("disabled", false);
            }

            var forwarders = responseJSON.response.forwarders;
            if (forwarders == null) {
                $("#txtForwarders").val("");
            }
            else {
                var value = "";

                for (var i = 0; i < forwarders.length; i++)
                    value += forwarders[i] + "\r\n";

                $("#txtForwarders").val(value);
            }

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

                case "httpsjson":
                    $("#rdForwarderProtocolHttpsJson").prop("checked", true);
                    break;

                default:
                    $("#rdForwarderProtocolUdp").prop("checked", true);
                    break;
            }

            $("#chkEnableBlocking").prop("checked", responseJSON.response.enableBlocking);
            $("#chkAllowTxtBlockingReport").prop("checked", responseJSON.response.allowTxtBlockingReport);

            if (responseJSON.response.temporaryDisableBlockingTill == null)
                $("#lblTemporaryDisableBlockingTill").text("Not Set");
            else
                $("#lblTemporaryDisableBlockingTill").text(moment(responseJSON.response.temporaryDisableBlockingTill).local().format("YYYY-MM-DD HH:mm:ss"));

            $("#txtTemporaryDisableBlockingMinutes").val("");

            $("#txtCustomBlockingAddresses").prop("disabled", true);

            switch (responseJSON.response.blockingType) {
                case "NxDomain":
                    $("#rdBlockingTypeNxDomain").prop("checked", true);
                    break;

                case "CustomAddress":
                    $("#rdBlockingTypeCustomAddress").prop("checked", true);
                    $("#txtCustomBlockingAddresses").prop("disabled", false);
                    break;

                case "AnyAddress":
                default:
                    $("#rdBlockingTypeAnyAddress").prop("checked", true);
                    break;
            }

            {
                var value = "";

                for (var i = 0; i < responseJSON.response.customBlockingAddresses.length; i++)
                    value += responseJSON.response.customBlockingAddresses[i] + "\r\n";

                $("#txtCustomBlockingAddresses").val(value);
            }

            var blockListUrls = responseJSON.response.blockListUrls;
            if (blockListUrls == null) {
                $("#txtBlockListUrls").val("");
                $("#btnUpdateBlockListsNow").prop("disabled", true);
            }
            else {
                var value = "";

                for (var i = 0; i < blockListUrls.length; i++)
                    value += blockListUrls[i] + "\r\n";

                $("#txtBlockListUrls").val(value);
                $("#btnUpdateBlockListsNow").prop("disabled", false);
            }

            $("#optQuickBlockList").val("blank");

            //fix custom block list url in case port changes
            {
                var optCustomLocalBlockList = $("#optCustomLocalBlockList");

                optCustomLocalBlockList.attr("value", "http://localhost:" + responseJSON.response.webServiceHttpPort + "/blocklist.txt");
                optCustomLocalBlockList.text("Custom Local Block List (http://localhost:" + responseJSON.response.webServiceHttpPort + "/blocklist.txt)");
            }

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

            divDnsSettingsLoader.hide();
            divDnsSettings.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divDnsSettingsLoader
    });
}

function saveDnsSettings() {
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

    var webServiceLocalAddresses = cleanTextList($("#txtWebServiceLocalAddresses").val());

    if ((webServiceLocalAddresses.length === 0) || (webServiceLocalAddresses === ","))
        webServiceLocalAddresses = "0.0.0.0,[::]";
    else
        $("#txtWebServiceLocalAddresses").val(webServiceLocalAddresses.replace(/,/g, "\n"));

    var webServiceHttpPort = $("#txtWebServiceHttpPort").val();

    if ((webServiceHttpPort === null) || (webServiceHttpPort === ""))
        webServiceHttpPort = 5380;

    var webServiceEnableTls = $("#chkWebServiceEnableTls").prop("checked");
    var webServiceHttpToTlsRedirect = $("#chkWebServiceHttpToTlsRedirect").prop("checked");
    var webServiceUseSelfSignedTlsCertificate = $("#chkWebServiceUseSelfSignedTlsCertificate").prop("checked");
    var webServiceTlsPort = $("#txtWebServiceTlsPort").val();
    var webServiceTlsCertificatePath = $("#txtWebServiceTlsCertificatePath").val();
    var webServiceTlsCertificatePassword = $("#txtWebServiceTlsCertificatePassword").val();

    var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop('checked');
    var enableDnsOverTls = $("#chkEnableDnsOverTls").prop('checked');
    var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop('checked');
    var dnsTlsCertificatePath = $("#txtDnsTlsCertificatePath").val();
    var dnsTlsCertificatePassword = $("#txtDnsTlsCertificatePassword").val();

    var tsigKeys = serializeTableData($("#tableTsigKeys"), 3);
    if (tsigKeys === false)
        return;

    if (tsigKeys.length === 0)
        tsigKeys = false;

    var defaultRecordTtl = $("#txtDefaultRecordTtl").val();
    var preferIPv6 = $("#chkPreferIPv6").prop('checked');

    var enableLogging = $("#chkEnableLogging").prop('checked');
    var logQueries = $("#chkLogQueries").prop('checked');
    var useLocalTime = $("#chkUseLocalTime").prop('checked');
    var logFolder = $("#txtLogFolderPath").val();
    var maxLogFileDays = $("#txtMaxLogFileDays").val();
    var maxStatFileDays = $("#txtMaxStatFileDays").val();

    var recursion = $("input[name=rdRecursion]:checked").val();

    var recursionDeniedNetworks = cleanTextList($("#txtRecursionDeniedNetworks").val());

    if ((recursionDeniedNetworks.length === 0) || (recursionDeniedNetworks === ","))
        recursionDeniedNetworks = false;
    else
        $("#txtRecursionDeniedNetworks").val(recursionDeniedNetworks.replace(/,/g, "\n"));

    var recursionAllowedNetworks = cleanTextList($("#txtRecursionAllowedNetworks").val());

    if ((recursionAllowedNetworks.length === 0) || (recursionAllowedNetworks === ","))
        recursionAllowedNetworks = false;
    else
        $("#txtRecursionAllowedNetworks").val(recursionAllowedNetworks.replace(/,/g, "\n"));

    var randomizeName = $("#chkRandomizeName").prop('checked');
    var qnameMinimization = $("#chkQnameMinimization").prop('checked');
    var nsRevalidation = $("#chkNsRevalidation").prop('checked');

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

    var serveStale = $("#chkServeStale").prop("checked");
    var serveStaleTtl = $("#txtServeStaleTtl").val();

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

    var enableBlocking = $("#chkEnableBlocking").prop("checked");
    var allowTxtBlockingReport = $("#chkAllowTxtBlockingReport").prop("checked");

    var blockingType = $("input[name=rdBlockingType]:checked").val();

    var customBlockingAddresses = cleanTextList($("#txtCustomBlockingAddresses").val());
    if ((customBlockingAddresses.length === 0) || customBlockingAddresses === ",")
        customBlockingAddresses = false;
    else
        $("#txtCustomBlockingAddresses").val(customBlockingAddresses.replace(/,/g, "\n") + "\n");

    var blockListUrls = cleanTextList($("#txtBlockListUrls").val());

    if ((blockListUrls.length === 0) || (blockListUrls === ","))
        blockListUrls = false;
    else
        $("#txtBlockListUrls").val(blockListUrls.replace(/,/g, "\n") + "\n");

    var blockListUpdateIntervalHours = $("#txtBlockListUpdateIntervalHours").val();

    var btn = $("#btnSaveDnsSettings").button('loading');

    HTTPRequest({
        url: "/api/setDnsSettings?token=" + token + "&dnsServerDomain=" + dnsServerDomain + "&dnsServerLocalEndPoints=" + encodeURIComponent(dnsServerLocalEndPoints)
            + "&webServiceLocalAddresses=" + encodeURIComponent(webServiceLocalAddresses) + "&webServiceHttpPort=" + webServiceHttpPort + "&webServiceEnableTls=" + webServiceEnableTls + "&webServiceHttpToTlsRedirect=" + webServiceHttpToTlsRedirect + "&webServiceUseSelfSignedTlsCertificate=" + webServiceUseSelfSignedTlsCertificate + "&webServiceTlsPort=" + webServiceTlsPort + "&webServiceTlsCertificatePath=" + encodeURIComponent(webServiceTlsCertificatePath) + "&webServiceTlsCertificatePassword=" + encodeURIComponent(webServiceTlsCertificatePassword)
            + "&enableDnsOverHttp=" + enableDnsOverHttp + "&enableDnsOverTls=" + enableDnsOverTls + "&enableDnsOverHttps=" + enableDnsOverHttps + "&dnsTlsCertificatePath=" + encodeURIComponent(dnsTlsCertificatePath) + "&dnsTlsCertificatePassword=" + encodeURIComponent(dnsTlsCertificatePassword)
            + "&tsigKeys=" + encodeURIComponent(tsigKeys)
            + "&defaultRecordTtl=" + defaultRecordTtl + "&preferIPv6=" + preferIPv6 + "&enableLogging=" + enableLogging + "&logQueries=" + logQueries + "&useLocalTime=" + useLocalTime + "&logFolder=" + encodeURIComponent(logFolder) + "&maxLogFileDays=" + maxLogFileDays + "&maxStatFileDays=" + maxStatFileDays
            + "&recursion=" + recursion + "&recursionDeniedNetworks=" + encodeURIComponent(recursionDeniedNetworks) + "&recursionAllowedNetworks=" + encodeURIComponent(recursionAllowedNetworks) + "&randomizeName=" + randomizeName + "&qnameMinimization=" + qnameMinimization + "&nsRevalidation=" + nsRevalidation
            + "&qpmLimitRequests=" + qpmLimitRequests + "&qpmLimitErrors=" + qpmLimitErrors + "&qpmLimitSampleMinutes=" + qpmLimitSampleMinutes + "&qpmLimitIPv4PrefixLength=" + qpmLimitIPv4PrefixLength + "&qpmLimitIPv6PrefixLength=" + qpmLimitIPv6PrefixLength
            + "&serveStale=" + serveStale + "&serveStaleTtl=" + serveStaleTtl + "&cacheMinimumRecordTtl=" + cacheMinimumRecordTtl + "&cacheMaximumRecordTtl=" + cacheMaximumRecordTtl + "&cacheNegativeRecordTtl=" + cacheNegativeRecordTtl + "&cacheFailureRecordTtl=" + cacheFailureRecordTtl + "&cachePrefetchEligibility=" + cachePrefetchEligibility + "&cachePrefetchTrigger=" + cachePrefetchTrigger + "&cachePrefetchSampleIntervalInMinutes=" + cachePrefetchSampleIntervalInMinutes + "&cachePrefetchSampleEligibilityHitsPerHour=" + cachePrefetchSampleEligibilityHitsPerHour
            + proxy + "&forwarders=" + encodeURIComponent(forwarders) + "&forwarderProtocol=" + forwarderProtocol + "&enableBlocking=" + enableBlocking + "&allowTxtBlockingReport=" + allowTxtBlockingReport + "&blockingType=" + blockingType + "&customBlockingAddresses=" + encodeURIComponent(customBlockingAddresses) + "&blockListUrls=" + encodeURIComponent(blockListUrls) + "&blockListUpdateIntervalHours=" + blockListUpdateIntervalHours,
        success: function (responseJSON) {
            document.title = responseJSON.response.dnsServerDomain + " - " + "Technitium DNS Server v" + responseJSON.response.version;
            $("#lblDnsServerDomain").text(" - " + responseJSON.response.dnsServerDomain);
            $("#txtDnsServerDomain").val(responseJSON.response.dnsServerDomain);

            $("#txtAddEditRecordTtl").attr("placeholder", responseJSON.response.defaultRecordTtl);

            //reset tls state
            $("#chkWebServiceEnableTls").prop("checked", responseJSON.response.webServiceEnableTls);
            $("#chkWebServiceHttpToTlsRedirect").prop("disabled", !responseJSON.response.webServiceEnableTls);
            $("#chkWebServiceUseSelfSignedTlsCertificate").prop("disabled", !responseJSON.response.webServiceEnableTls);
            $("#txtWebServiceTlsPort").prop("disabled", !responseJSON.response.webServiceEnableTls);
            $("#txtWebServiceTlsCertificatePath").prop("disabled", !responseJSON.response.webServiceEnableTls);
            $("#txtWebServiceTlsCertificatePassword").prop("disabled", !responseJSON.response.webServiceEnableTls);

            //reload tsig keys
            $("#tableTsigKeys").html("");

            if (responseJSON.response.tsigKeys != null) {
                for (var i = 0; i < responseJSON.response.tsigKeys.length; i++) {
                    addTsigKeyRow(responseJSON.response.tsigKeys[i].keyName, responseJSON.response.tsigKeys[i].sharedSecret, responseJSON.response.tsigKeys[i].algorithmName);
                }

                updateTsigKeyNamesDropdowns(responseJSON.response.tsigKeys);
            }

            //fix custom block list url in case port changes
            {
                var optCustomLocalBlockList = $("#optCustomLocalBlockList");

                optCustomLocalBlockList.attr("value", "http://localhost:" + responseJSON.response.webServiceHttpPort + "/blocklist.txt");
                optCustomLocalBlockList.text("Custom Local Block List (http://localhost:" + responseJSON.response.webServiceHttpPort + "/blocklist.txt)");
            }

            if (enableBlocking)
                $("#lblTemporaryDisableBlockingTill").text("Not Set");

            //reload forwarders
            var forwarders = responseJSON.response.forwarders;
            if (forwarders == null) {
                $("#txtForwarders").val("");
            }
            else {
                var value = "";

                for (var i = 0; i < forwarders.length; i++)
                    value += forwarders[i] + "\r\n";

                $("#txtForwarders").val(value);
            }

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

function updateTsigKeyNamesDropdowns(tsigKeys) {
    var optionsHtml = "<option selected></option>";

    for (var i = 0; i < tsigKeys.length; i++) {
        optionsHtml += "<option>" + htmlEncode(tsigKeys[i].keyName) + "</option>";
    }

    $("#optAddZoneTsigKeyName").html(optionsHtml);
    $("#optEditRecordDataSoaTsigKeyName").html(optionsHtml);
}

function checkForReverseProxy(responseJSON) {
    if (window.location.protocol == "https:") {
        var currentPort = window.location.port;

        if ((currentPort == 0) || (currentPort == ""))
            currentPort = 443;

        reverseProxyDetected = currentPort != responseJSON.response.webServiceTlsPort;
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
            window.open("http://" + window.location.hostname + ":" + responseJSON.response.webServiceHttpPort, "_self");
            return;
        }

        var currentPort = window.location.port;

        if ((currentPort == 0) || (currentPort == ""))
            currentPort = 443;

        if (currentPort != responseJSON.response.webServiceTlsPort)
            window.open("https://" + window.location.hostname + ":" + responseJSON.response.webServiceTlsPort, "_self");
    }
    else {
        if (responseJSON.response.webServiceEnableTls && responseJSON.response.webServiceHttpToTlsRedirect) {
            window.open("https://" + window.location.hostname + ":" + responseJSON.response.webServiceTlsPort, "_self");
            return;
        }

        var currentPort = window.location.port;

        if ((currentPort == 0) || (currentPort == ""))
            currentPort = 80;

        if (currentPort != responseJSON.response.webServiceHttpPort)
            window.open("http://" + window.location.hostname + ":" + responseJSON.response.webServiceHttpPort, "_self");
    }
}

function forceUpdateBlockLists() {
    if (!confirm("Are you sure to force download and update the block lists?"))
        return;

    var btn = $("#btnUpdateBlockListsNow").button('loading');

    HTTPRequest({
        url: "/api/forceUpdateBlockLists?token=" + token,
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

    var btn = $("#btnTemporaryDisableBlockingNow").button('loading');

    HTTPRequest({
        url: "/api/temporaryDisableBlocking?token=" + token + "&minutes=" + minutes,
        success: function (responseJSON) {
            btn.button('reset');

            $("#chkEnableBlocking").prop("checked", false);
            $("#lblTemporaryDisableBlockingTill").text(moment(responseJSON.response.temporaryDisableBlockingTill).local().format("YYYY-MM-DD HH:mm:ss"));

            showAlert("success", "Blocking Disabled!", "Blocking was successfully disabled temporarily for " + htmlEncode(minutes) + " minute(s).");
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
        var start = $("#dpCustomDayWiseStart").val();
        if (start === null || (start === "")) {
            showAlert("warning", "Missing!", "Please select a start date.");
            $("#dpCustomDayWiseStart").focus();
            return;
        }

        var end = $("#dpCustomDayWiseEnd").val();
        if (end === null || (end === "")) {
            showAlert("warning", "Missing!", "Please select an end date.");
            $("#dpCustomDayWiseEnd").focus();
            return;
        }

        custom = "&start=" + start + "&end=" + end;
    }

    if (!hideLoader) {
        divDashboard.hide();
        divDashboardLoader.show();
    }

    HTTPRequest({
        url: "/api/getStats?token=" + token + "&type=" + type + custom,
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

            $("#divDashboardStatsTotalClients").text(responseJSON.response.stats.totalClients.toLocaleString());

            $("#divDashboardStatsZones").text(responseJSON.response.stats.zones.toLocaleString());
            $("#divDashboardStatsAllowedZones").text(responseJSON.response.stats.allowedZones.toLocaleString());
            $("#divDashboardStatsBlockedZones").text(responseJSON.response.stats.blockedZones.toLocaleString());
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
            }

            //main chart
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

            //top clients
            {
                var tableHtmlRows;
                var topClients = responseJSON.response.topClients;

                if (topClients.length < 1) {
                    tableHtmlRows = "<tr><td colspan=\"2\" align=\"center\">No Data</td></tr>";
                }
                else {
                    tableHtmlRows = "";

                    for (var i = 0; i < topClients.length; i++) {
                        tableHtmlRows += "<tr><td>" + htmlEncode(topClients[i].name) + "<br />" + htmlEncode(topClients[i].domain == "" ? "." : topClients[i].domain) + "</td><td>" + topClients[i].hits.toLocaleString() + "</td></tr>";
                    }
                }

                $("#tableTopClients").html(tableHtmlRows);
            }

            //top domains
            {
                var tableHtmlRows;
                var topDomains = responseJSON.response.topDomains;

                if (topDomains.length < 1) {
                    tableHtmlRows = "<tr><td colspan=\"2\" align=\"center\">No Data</td></tr>";
                }
                else {
                    tableHtmlRows = "";

                    for (var i = 0; i < topDomains.length; i++) {
                        tableHtmlRows += "<tr><td>" + htmlEncode(topDomains[i].name == "" ? "." : topDomains[i].name) + "</td><td>" + topDomains[i].hits.toLocaleString() + "</td></tr>";
                    }
                }

                $("#tableTopDomains").html(tableHtmlRows);
            }

            //top blocked domains
            {
                var tableHtmlRows;
                var topBlockedDomains = responseJSON.response.topBlockedDomains;

                if (topBlockedDomains.length < 1) {
                    tableHtmlRows = "<tr><td colspan=\"2\" align=\"center\">No Data</td></tr>";
                }
                else {
                    tableHtmlRows = "";

                    for (var i = 0; i < topBlockedDomains.length; i++) {
                        tableHtmlRows += "<tr><td>" + htmlEncode(topBlockedDomains[i].name == "" ? "." : topBlockedDomains[i].name) + "</td><td>" + topBlockedDomains[i].hits.toLocaleString() + "</td></tr>";
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
        var start = $("#dpCustomDayWiseStart").val();
        if (start === null || (start === "")) {
            showAlert("warning", "Missing!", "Please select a start date.");
            $("#dpCustomDayWiseStart").focus();
            return;
        }

        var end = $("#dpCustomDayWiseEnd").val();
        if (end === null || (end === "")) {
            showAlert("warning", "Missing!", "Please select an end date.");
            $("#dpCustomDayWiseEnd").focus();
            return;
        }

        custom = "&start=" + start + "&end=" + end;
    }

    HTTPRequest({
        url: "/api/getTopStats?token=" + token + "&type=" + type + custom + "&statsType=" + statsType + "&limit=" + limit,
        success: function (responseJSON) {
            divTopStatsLoader.hide();

            if (responseJSON.response.topClients != null) {
                var tableHtmlRows;
                var topClients = responseJSON.response.topClients;

                if (topClients.length < 1) {
                    tableHtmlRows = "<tr><td colspan=\"2\" align=\"center\">No Data</td></tr>";
                }
                else {
                    tableHtmlRows = "";

                    for (var i = 0; i < topClients.length; i++) {
                        tableHtmlRows += "<tr><td>" + htmlEncode(topClients[i].name) + "<br />" + htmlEncode(topClients[i].domain == "" ? "." : topClients[i].domain) + "</td><td>" + topClients[i].hits.toLocaleString() + "</td></tr>";
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
                    tableHtmlRows = "<tr><td colspan=\"2\" align=\"center\">No Data</td></tr>";
                }
                else {
                    tableHtmlRows = "";

                    for (var i = 0; i < topDomains.length; i++) {
                        tableHtmlRows += "<tr><td>" + htmlEncode(topDomains[i].name == "" ? "." : topDomains[i].name) + "</td><td>" + topDomains[i].hits.toLocaleString() + "</td></tr>";
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
                    tableHtmlRows = "<tr><td colspan=\"2\" align=\"center\">No Data</td></tr>";
                }
                else {
                    tableHtmlRows = "";

                    for (var i = 0; i < topBlockedDomains.length; i++) {
                        tableHtmlRows += "<tr><td>" + htmlEncode(topBlockedDomains[i].name == "" ? "." : topBlockedDomains[i].name) + "</td><td>" + topBlockedDomains[i].hits.toLocaleString() + "</td></tr>";
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

    if (server.indexOf("recursive-resolver") !== -1)
        $("#optDnsClientProtocol").val("UDP");

    var domain = $("#txtDnsClientDomain").val();
    var type = $("#optDnsClientType").val();
    var protocol = $("#optDnsClientProtocol").val();

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
        if (!confirm("Importing all the records from the result of this query will overwrite existing records in the zone or if the zone does not exists, a new primary zone '" + domain + "' will be created.\n\nAre you sure you want to import all records?"))
            return;
    }

    var btn = $(importRecords ? "#btnDnsClientImport" : "#btnDnsClientResolve").button('loading');
    var btnOther = $(importRecords ? "#btnDnsClientResolve" : "#btnDnsClientImport").prop("disabled", true);

    var divDnsClientLoader = $("#divDnsClientLoader");
    var preDnsClientOutput = $("#preDnsClientOutput");

    preDnsClientOutput.hide();
    divDnsClientLoader.show();

    HTTPRequest({
        url: "/api/resolveQuery?token=" + token + "&server=" + encodeURIComponent(server) + "&domain=" + encodeURIComponent(domain) + "&type=" + type + "&protocol=" + protocol + (importRecords ? "&import=true" : ""),
        success: function (responseJSON) {
            preDnsClientOutput.text(JSON.stringify(responseJSON.response.result, null, 2));

            preDnsClientOutput.show();
            divDnsClientLoader.hide();

            btn.button('reset');
            btnOther.prop("disabled", false);

            if (importRecords) {
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

function resetBackupSettingsModal() {
    $("#divBackupSettingsAlert").html("");

    $("#chkBackupDnsSettings").prop("checked", true);
    $("#chkBackupLogSettings").prop("checked", true);
    $("#chkBackupZones").prop("checked", true);
    $("#chkBackupAllowedZones").prop("checked", true);
    $("#chkBackupBlockedZones").prop("checked", true);
    $("#chkBackupScopes").prop("checked", true);
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
    var logSettings = $("#chkBackupLogSettings").prop('checked');

    if (!blockLists && !logs && !scopes && !apps && !stats && !zones && !allowedZones && !blockedZones && !dnsSettings && !logSettings) {
        showAlert("warning", "Missing!", "Please select at least one item to backup.", divBackupSettingsAlert);
        return;
    }

    window.open("/api/backupSettings?token=" + token + "&blockLists=" + blockLists + "&logs=" + logs + "&scopes=" + scopes + "&apps=" + apps + "&stats=" + stats + "&zones=" + zones + "&allowedZones=" + allowedZones + "&blockedZones=" + blockedZones + "&dnsSettings=" + dnsSettings + "&logSettings=" + logSettings + "&ts=" + (new Date().getTime()), "_blank");

    $("#modalBackupSettings").modal("hide");
    showAlert("success", "Backed Up!", "Settings were backed up successfully.");
}

function resetRestoreSettingsModal() {
    $("#divRestoreSettingsAlert").html("");

    $("#fileBackupZip").val("");

    $("#chkRestoreDnsSettings").prop("checked", true);
    $("#chkRestoreLogSettings").prop("checked", true);
    $("#chkRestoreZones").prop("checked", true);
    $("#chkRestoreAllowedZones").prop("checked", true);
    $("#chkRestoreBlockedZones").prop("checked", true);
    $("#chkRestoreScopes").prop("checked", true);
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
    var logSettings = $("#chkRestoreLogSettings").prop('checked');

    var deleteExistingFiles = $("#chkDeleteExistingFiles").prop('checked');

    if (!blockLists && !logs && !scopes && !apps && !stats && !zones && !allowedZones && !blockedZones && !dnsSettings && !logSettings) {
        showAlert("warning", "Missing!", "Please select at least one item to restore.", divRestoreSettingsAlert);
        return;
    }

    var formData = new FormData();
    formData.append("fileBackupZip", $("#fileBackupZip")[0].files[0]);

    var btn = $("#btnRestoreSettings").button('loading');

    HTTPRequest({
        url: "/api/restoreSettings?token=" + token + "&blockLists=" + blockLists + "&logs=" + logs + "&scopes=" + scopes + "&apps=" + apps + "&stats=" + stats + "&zones=" + zones + "&allowedZones=" + allowedZones + "&blockedZones=" + blockedZones + "&dnsSettings=" + dnsSettings + "&logSettings=" + logSettings + "&deleteExistingFiles=" + deleteExistingFiles,
        data: formData,
        dataIsFormData: true,
        success: function (responseJSON) {
            document.title = responseJSON.response.dnsServerDomain + " - " + "Technitium DNS Server v" + responseJSON.response.version;
            $("#lblDnsServerDomain").text(" - " + responseJSON.response.dnsServerDomain);
            $("#txtDnsServerDomain").val(responseJSON.response.dnsServerDomain);

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