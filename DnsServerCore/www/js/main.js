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
var quickBlockLists = null;
var quickForwardersList = null;

function showPageLogin() {
    hideAlert();

    localStorage.removeItem("token");

    $("#pageMain").hide();
    $("#mnuUser").hide();

    $("#txtUser").val("");
    $("#txtPass").val("");
    $("#txtPass").prop("disabled", false);
    $("#div2FAOTP").hide();
    $("#txt2FATOTP").val("");
    $("#btnLogin").button("reset");
    $("#pageLogin").show();

    $("#txtUser").trigger("focus");

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

    updateAllClusterNodeDropDowns();

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
        refreshCachedZonesList("");
    }
    else {
        $("#mainPanelTabListCachedZones").hide();
    }

    if (sessionData.info.permissions.Allowed.canView) {
        $("#mainPanelTabListAllowedZones").show();
        refreshAllowedZonesList("");
    }
    else {
        $("#mainPanelTabListAllowedZones").hide();
    }

    if (sessionData.info.permissions.Blocked.canView) {
        $("#mainPanelTabListBlockedZones").show();
        refreshBlockedZonesList("");
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
        var type = $("input[name=rdStatType]:checked").val();
        if (type === "lastHour")
            refreshDashboard(true);

        $("#lblAboutUptime").text(moment(sessionData.info.uptimestamp).local().format("lll") + " (" + moment(sessionData.info.uptimestamp).fromNow() + ")");
    }, 60000);
}

$(function () {
    var headerHtml = $("#header").html();

    $("#header").html("<div class=\"title\"><a href=\".\"><img src=\"img/logo25x25.png\" alt=\"Technitium Logo\" /><span class=\"text\" style=\"color: #ffffff;\">Technitium</span></a>" + headerHtml + "</div>");
    $("#footer").html("<div class=\"content\"><a href=\"https://technitium.com/\" target=\"_blank\">Technitium</a> | <a href=\"https://blog.technitium.com/\" target=\"_blank\">Blog</a> | <a href=\"https://go.technitium.com/?id=35\" target=\"_blank\">Donate</a> | <a href=\"https://dnsclient.net/\" target=\"_blank\">DNS Client</a> | <a href=\"https://github.com/TechnitiumSoftware/DnsServer\" target=\"_blank\"><i class=\"fa fa-github\"></i>&nbsp;GitHub</a> | <a href=\"#\" onclick=\"showAbout(); return false;\">About</a></div>");

    loadQuickBlockLists();
    loadQuickForwardersList();

    $("#chkEnableUdpSocketPool").on("click", function () {
        var enableUdpSocketPool = $("#chkEnableUdpSocketPool").prop("checked");

        $("#txtUdpSocketPoolExcludedPorts").prop("disabled", !enableUdpSocketPool);
    });

    $("#chkEDnsClientSubnet").on("click", function () {
        var eDnsClientSubnet = $("#chkEDnsClientSubnet").prop("checked");

        $("#txtEDnsClientSubnetIPv4PrefixLength").prop("disabled", !eDnsClientSubnet);
        $("#txtEDnsClientSubnetIPv6PrefixLength").prop("disabled", !eDnsClientSubnet);
        $("#txtEDnsClientSubnetIpv4Override").prop("disabled", !eDnsClientSubnet);
        $("#txtEDnsClientSubnetIpv6Override").prop("disabled", !eDnsClientSubnet);
    });

    $("#chkEnableBlocking").on("click", updateBlockingState);

    $("input[type=radio][name=rdProxyType]").on("change", function () {
        var proxyType = $("input[name=rdProxyType]:checked").val().toLowerCase();
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

    $("input[type=radio][name=rdRecursion]").on("change", function () {
        var recursion = $("input[name=rdRecursion]:checked").val();

        $("#txtRecursionNetworkACL").prop("disabled", recursion !== "UseSpecifiedNetworkACL");
    });

    $("input[type=radio][name=rdBlockingType]").on("change", function () {
        var recursion = $("input[name=rdBlockingType]:checked").val();
        if (recursion === "CustomAddress") {
            $("#txtCustomBlockingAddresses").prop("disabled", false);
        }
        else {
            $("#txtCustomBlockingAddresses").prop("disabled", true);
        }
    });

    $("#chkWebServiceEnableTls").on("click", function () {
        var webServiceEnableTls = $("#chkWebServiceEnableTls").prop("checked");
        $("#chkWebServiceEnableHttp3").prop("disabled", !webServiceEnableTls);
        $("#chkWebServiceHttpToTlsRedirect").prop("disabled", !webServiceEnableTls);
        $("#chkWebServiceUseSelfSignedTlsCertificate").prop("disabled", !webServiceEnableTls);
        $("#txtWebServiceTlsPort").prop("disabled", !webServiceEnableTls);
        $("#txtWebServiceTlsCertificatePath").prop("disabled", !webServiceEnableTls);
        $("#txtWebServiceTlsCertificatePassword").prop("disabled", !webServiceEnableTls);
    });

    $("#chkEnableDnsOverUdpProxy").on("click", function () {
        var enableDnsOverUdpProxy = $("#chkEnableDnsOverUdpProxy").prop("checked");
        var enableDnsOverTcpProxy = $("#chkEnableDnsOverTcpProxy").prop("checked");
        var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");

        $("#txtDnsOverUdpProxyPort").prop("disabled", !enableDnsOverUdpProxy);
        $("#txtReverseProxyNetworkACL").prop("disabled", !enableDnsOverUdpProxy && !enableDnsOverTcpProxy && !enableDnsOverHttp && !enableDnsOverHttps);
    });

    $("#chkEnableDnsOverTcpProxy").on("click", function () {
        var enableDnsOverUdpProxy = $("#chkEnableDnsOverUdpProxy").prop("checked");
        var enableDnsOverTcpProxy = $("#chkEnableDnsOverTcpProxy").prop("checked");
        var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");

        $("#txtDnsOverTcpProxyPort").prop("disabled", !enableDnsOverTcpProxy);
        $("#txtReverseProxyNetworkACL").prop("disabled", !enableDnsOverUdpProxy && !enableDnsOverTcpProxy && !enableDnsOverHttp && !enableDnsOverHttps);
    });

    $("#chkEnableDnsOverHttp").on("click", function () {
        var enableDnsOverUdpProxy = $("#chkEnableDnsOverUdpProxy").prop("checked");
        var enableDnsOverTcpProxy = $("#chkEnableDnsOverTcpProxy").prop("checked");
        var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");

        $("#txtDnsOverHttpPort").prop("disabled", !enableDnsOverHttp);
        $("#txtReverseProxyNetworkACL").prop("disabled", !enableDnsOverUdpProxy && !enableDnsOverTcpProxy && !enableDnsOverHttp && !enableDnsOverHttps);
        $("#txtDnsOverHttpRealIpHeader").prop("disabled", !enableDnsOverHttp && !enableDnsOverHttps);
    });

    $("#chkEnableDnsOverTls").on("click", function () {
        var enableDnsOverTls = $("#chkEnableDnsOverTls").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");
        var enableDnsOverQuic = $("#chkEnableDnsOverQuic").prop("checked");

        $("#txtDnsOverTlsPort").prop("disabled", !enableDnsOverTls);
        $("#txtDnsTlsCertificatePath").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic);
        $("#txtDnsTlsCertificatePassword").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic);
    });

    $("#chkEnableDnsOverHttps").on("click", function () {
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

    $("#chkEnableDnsOverQuic").on("click", function () {
        var enableDnsOverTls = $("#chkEnableDnsOverTls").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");
        var enableDnsOverQuic = $("#chkEnableDnsOverQuic").prop("checked");

        $("#txtDnsOverQuicPort").prop("disabled", !enableDnsOverQuic);
        $("#txtDnsTlsCertificatePath").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic);
        $("#txtDnsTlsCertificatePassword").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic);
    });

    $("#chkEnableConcurrentForwarding").on("click", function () {
        var concurrentForwarding = $("#chkEnableConcurrentForwarding").prop("checked");
        $("#txtForwarderConcurrency").prop("disabled", !concurrentForwarding)
    });

    $("input[type=radio][name=rdLoggingType]").on("change", function () {
        var rdLoggingType = $("input[name=rdLoggingType]:checked").val();
        var enableLogging = rdLoggingType.toLowerCase() != "none";

        $("#chkIgnoreResolverLogs").prop("disabled", !enableLogging);
        $("#chkLogQueries").prop("disabled", !enableLogging);
        $("#chkUseLocalTime").prop("disabled", !enableLogging);
        $("#txtLogFolderPath").prop("disabled", !enableLogging);
    });

    $("#chkServeStale").on("click", function () {
        var serveStale = $("#chkServeStale").prop("checked");
        $("#txtServeStaleTtl").prop("disabled", !serveStale);
    });

    $("#optQuickBlockList").on("change", function () {
        var selectedOption = $("#optQuickBlockList").val();

        switch (selectedOption) {
            case "blank":
                break;

            case "none":
                $("#txtBlockListUrls").val("");
                break;

            default:
                for (var i = 0; i < quickBlockLists.length; i++) {
                    if (quickBlockLists[i].name === selectedOption) {
                        var existingList;

                        if (selectedOption.toLowerCase() == "default")
                            existingList = "";
                        else
                            existingList = $("#txtBlockListUrls").val();

                        var newList = existingList;

                        for (var j = 0; j < quickBlockLists[i].urls.length; j++) {
                            var url = quickBlockLists[i].urls[j];

                            if (existingList.indexOf(url) < 0)
                                newList += url + "\n";
                        }

                        $("#txtBlockListUrls").val(newList);
                        break;
                    }
                }

                break;
        }
    });

    $("#optQuickForwarders").on("change", function () {
        var selectedOption = $("#optQuickForwarders").val();

        switch (selectedOption) {
            case "blank":
                break;

            case "none":
                $("#txtForwarders").val("");
                $("#rdForwarderProtocolUdp").prop("checked", true);
                break;

            default:
                for (var i = 0; i < quickForwardersList.length; i++) {
                    if (quickForwardersList[i].name === selectedOption) {
                        var forwarders = "";

                        for (var j = 0; j < quickForwardersList[i].addresses.length; j++) {
                            forwarders += quickForwardersList[i].addresses[j] + "\n";
                        }

                        $("#txtForwarders").val(forwarders);

                        switch (quickForwardersList[i].protocol.toUpperCase()) {
                            case "TCP":
                                $("#rdForwarderProtocolTcp").prop("checked", true);
                                break;

                            case "TLS":
                                $("#rdForwarderProtocolTls").prop("checked", true);
                                break;

                            case "HTTPS":
                                $("#rdForwarderProtocolHttps").prop("checked", true);
                                break;

                            case "QUIC":
                                $("#rdForwarderProtocolQuic").prop("checked", true);
                                break;

                            default:
                                $("#rdForwarderProtocolUdp").prop("checked", true);
                                break;
                        }

                        if (quickForwardersList[i].proxyType == null)
                            quickForwardersList[i].proxyType = "DefaultProxy";

                        switch (quickForwardersList[i].proxyType.toUpperCase()) {
                            case "SOCKS5":
                            case "HTTP":
                                if (quickForwardersList[i].proxyType.toUpperCase() == "SOCKS5")
                                    $("#rdProxyTypeSocks5").prop("checked", true);
                                else
                                    $("#rdProxyTypeHttp").prop("checked", true);

                                $("#txtProxyAddress").val(quickForwardersList[i].proxyAddress);
                                $("#txtProxyPort").val(quickForwardersList[i].proxyPort);
                                $("#txtProxyUsername").val(quickForwardersList[i].proxyUsername);
                                $("#txtProxyPassword").val(quickForwardersList[i].proxyPassword);

                                $("#txtProxyAddress").prop("disabled", false);
                                $("#txtProxyPort").prop("disabled", false);
                                $("#txtProxyUsername").prop("disabled", false);
                                $("#txtProxyPassword").prop("disabled", false);
                                break;

                            case "NONE":
                                $("#rdProxyTypeNone").prop("checked", true);

                                $("#txtProxyAddress").prop("disabled", true);
                                $("#txtProxyPort").prop("disabled", true);
                                $("#txtProxyUsername").prop("disabled", true);
                                $("#txtProxyPassword").prop("disabled", true);

                                $("#txtProxyAddress").val("");
                                $("#txtProxyPort").val("");
                                $("#txtProxyUsername").val("");
                                $("#txtProxyPassword").val("");
                                break;
                        }

                        break;
                    }
                }

                break;
        }
    });

    $("input[type=radio][name=rdStatType]").on("change", function () {
        var type = $("input[name=rdStatType]:checked").val();
        if (type === "custom") {
            $("#divCustomDayWise").show();

            if ($("#dpCustomDayWiseStart").val() === "") {
                $("#dpCustomDayWiseStart").trigger("focus");
                return;
            }

            if ($("#dpCustomDayWiseEnd").val() === "") {
                $("#dpCustomDayWiseEnd").trigger("focus");
                return;
            }

            refreshDashboard();
        }
        else {
            $("#divCustomDayWise").hide();

            refreshDashboard();
        }
    });

    $("#btnCustomDayWise").on("click", function () {
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
        url: "api/user/checkForUpdate?token=" + sessionData.token,
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

function loadQuickBlockLists() {
    $.ajax({
        type: "GET",
        url: "json/quick-block-lists-custom.json",
        dataType: "json",
        cache: false,
        async: false,
        success: function (responseJSON, status, jqXHR) {
            loadQuickBlockListsFrom(responseJSON);
        },
        error: function (jqXHR, textStatus, errorThrown) {
            $.ajax({
                type: "GET",
                url: "json/quick-block-lists-builtin.json",
                dataType: "json",
                cache: false,
                async: false,
                success: function (responseJSON, status, jqXHR) {
                    loadQuickBlockListsFrom(responseJSON);
                },
                error: function (jqXHR, textStatus, errorThrown) {
                    showAlert("danger", "Error!", "Failed to load Quick Forwarders list: " + jqXHR.status + " " + jqXHR.statusText);
                }
            });
        }
    });
}

function loadQuickBlockListsFrom(responseJSON) {
    var htmlList = "<option value=\"blank\" selected></option><option value=\"none\">None</option>";

    for (var i = 0; i < responseJSON.length; i++) {
        htmlList += "<option>" + htmlEncode(responseJSON[i].name) + "</option>";
    }

    quickBlockLists = responseJSON;
    $("#optQuickBlockList").html(htmlList);
}

function loadQuickForwardersList() {
    $.ajax({
        type: "GET",
        url: "json/quick-forwarders-list-custom.json",
        dataType: "json",
        cache: false,
        async: false,
        success: function (responseJSON, status, jqXHR) {
            loadQuickForwardersListFrom(responseJSON);
        },
        error: function (jqXHR, textStatus, errorThrown) {
            $.ajax({
                type: "GET",
                url: "json/quick-forwarders-list-builtin.json",
                dataType: "json",
                cache: false,
                async: false,
                success: function (responseJSON, status, jqXHR) {
                    loadQuickForwardersListFrom(responseJSON);
                },
                error: function (jqXHR, textStatus, errorThrown) {
                    showAlert("danger", "Error!", "Failed to load Quick Forwarders list: " + jqXHR.status + " " + jqXHR.statusText);
                }
            });
        }
    });
}

function loadQuickForwardersListFrom(responseJSON) {
    var htmlList = "<option value=\"blank\" selected></option><option value=\"none\">None</option>";

    for (var i = 0; i < responseJSON.length; i++) {
        htmlList += "<option>" + htmlEncode(responseJSON[i].name) + "</option>";
    }

    quickForwardersList = responseJSON;
    $("#optQuickForwarders").html(htmlList);
}

function refreshDnsSettings() {
    var divDnsSettingsLoader = $("#divDnsSettingsLoader");
    var divDnsSettings = $("#divDnsSettings");

    var node = $("#optSettingsClusterNode").val();

    divDnsSettings.hide();
    divDnsSettingsLoader.show();

    HTTPRequest({
        url: "api/settings/get?token=" + sessionData.token + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            if ((node == "") || (node == "cluster") || (node == sessionData.info.dnsServerDomain))
                updateDnsSettingsDataAndGui(responseJSON);

            loadDnsSettings(responseJSON);
            checkForReverseProxy(responseJSON);

            if (node == "cluster") {
                //cluster view
                //general
                $("#divSettingsGeneralLocalParameters").hide();
                $("#divSettingsGeneralDefaultParameters").show();
                $("#divSettingsGeneralDnsApps").show();
                $("#divSettingsGeneralIpv6").hide();
                $("#divSettingsGeneralUdpSocketPool").hide();
                $("#divSettingsGeneralEDns").show();
                $("#divSettingsGeneralDnssec").show();
                $("#divSettingsGeneralEDnsClientSubnet").show();
                $("#divSettingsGeneralRateLimiting").show();
                $("#divSettingsGeneralAdvancedOptions").show();

                //web service
                $("#settingsTabListWebService").hide();

                if ($("#settingsTabListWebService").hasClass("active")) {
                    $("#settingsTabListWebService").removeClass("active");
                    $("#settingsTabPaneWebService").removeClass("active");

                    $("#settingsTabListGeneral").addClass("active");
                    $("#settingsTabPaneGeneral").addClass("active");
                }

                //optional protocols
                $("#settingsTabListOptionalProtocols").hide();

                if ($("#settingsTabListOptionalProtocols").hasClass("active")) {
                    $("#settingsTabListOptionalProtocols").removeClass("active");
                    $("#settingsTabPaneOptionalProtocols").removeClass("active");

                    $("#settingsTabListGeneral").addClass("active");
                    $("#settingsTabPaneGeneral").addClass("active");
                }

                //tsig
                $("#settingsTabListTsig").show();

                //recursion
                $("#settingsTabListRecursion").show();

                //cache
                $("#settingsTabListCache").hide();

                if ($("#settingsTabListCache").hasClass("active")) {
                    $("#settingsTabListCache").removeClass("active");
                    $("#settingsTabPaneCache").removeClass("active");

                    $("#settingsTabListGeneral").addClass("active");
                    $("#settingsTabPaneGeneral").addClass("active");
                }

                //blocking
                $("#settingsTabListBlocking").show();

                //proxy & forwarders
                $("#settingsTabListProxyForwarders").show();

                //logging
                $("#settingsTabListLogging").hide();

                if ($("#settingsTabListLogging").hasClass("active")) {
                    $("#settingsTabListLogging").removeClass("active");
                    $("#settingsTabPaneLogging").removeClass("active");

                    $("#settingsTabListGeneral").addClass("active");
                    $("#settingsTabPaneGeneral").addClass("active");
                }

                //buttons
                $("#btnSettingsFlushCache").hide();
                $("#btnShowBackupSettingsModal").hide();
                $("#btnShowRestoreSettingsModal").hide();
            }
            else if (node != "") {
                //node view
                //general
                $("#divSettingsGeneralLocalParameters").show();
                $("#divSettingsGeneralDefaultParameters").hide();
                $("#divSettingsGeneralDnsApps").hide();
                $("#divSettingsGeneralIpv6").show();
                $("#divSettingsGeneralUdpSocketPool").show();
                $("#divSettingsGeneralEDns").hide();
                $("#divSettingsGeneralDnssec").hide();
                $("#divSettingsGeneralEDnsClientSubnet").hide();
                $("#divSettingsGeneralRateLimiting").hide();
                $("#divSettingsGeneralAdvancedOptions").hide();

                //web service
                $("#settingsTabListWebService").show();

                //optional protocols
                $("#settingsTabListOptionalProtocols").show();

                //tsig
                $("#settingsTabListTsig").hide();

                if ($("#settingsTabListTsig").hasClass("active")) {
                    $("#settingsTabListTsig").removeClass("active");
                    $("#settingsTabPaneTsig").removeClass("active");

                    $("#settingsTabListGeneral").addClass("active");
                    $("#settingsTabPaneGeneral").addClass("active");
                }

                //recursion
                $("#settingsTabListRecursion").hide();

                if ($("#settingsTabListRecursion").hasClass("active")) {
                    $("#settingsTabListRecursion").removeClass("active");
                    $("#settingsTabPaneRecursion").removeClass("active");

                    $("#settingsTabListGeneral").addClass("active");
                    $("#settingsTabPaneGeneral").addClass("active");
                }

                //cache
                $("#settingsTabListCache").show();

                //blocking
                $("#settingsTabListBlocking").hide();

                if ($("#settingsTabListBlocking").hasClass("active")) {
                    $("#settingsTabListBlocking").removeClass("active");
                    $("#settingsTabPaneBlocking").removeClass("active");

                    $("#settingsTabListGeneral").addClass("active");
                    $("#settingsTabPaneGeneral").addClass("active");
                }

                //proxy & forwarders
                $("#settingsTabListProxyForwarders").hide();

                if ($("#settingsTabListProxyForwarders").hasClass("active")) {
                    $("#settingsTabListProxyForwarders").removeClass("active");
                    $("#settingsTabPaneProxyForwarders").removeClass("active");

                    $("#settingsTabListGeneral").addClass("active");
                    $("#settingsTabPaneGeneral").addClass("active");
                }

                //logging
                $("#settingsTabListLogging").show();

                //buttons
                $("#btnSettingsFlushCache").show();
                $("#btnShowBackupSettingsModal").show();
                $("#btnShowRestoreSettingsModal").show();
            }
            else {
                //clustering disabled
                //general
                $("#divSettingsGeneralLocalParameters").show();
                $("#divSettingsGeneralDefaultParameters").show();
                $("#divSettingsGeneralDnsApps").show();
                $("#divSettingsGeneralIpv6").show();
                $("#divSettingsGeneralUdpSocketPool").show();
                $("#divSettingsGeneralEDns").show();
                $("#divSettingsGeneralDnssec").show();
                $("#divSettingsGeneralEDnsClientSubnet").show();
                $("#divSettingsGeneralRateLimiting").show();
                $("#divSettingsGeneralAdvancedOptions").show();

                //web service
                $("#settingsTabListWebService").show();

                //optional protocols
                $("#settingsTabListOptionalProtocols").show();

                //tsig
                $("#settingsTabListTsig").show();

                //recursion
                $("#settingsTabListRecursion").show();

                //cache
                $("#settingsTabListCache").show();

                //blocking
                $("#settingsTabListBlocking").show();

                //proxy & forwarders
                $("#settingsTabListProxyForwarders").show();

                //logging
                $("#settingsTabListLogging").show();

                //buttons
                $("#btnSettingsFlushCache").show();
                $("#btnShowBackupSettingsModal").show();
                $("#btnShowRestoreSettingsModal").show();
            }

            divDnsSettingsLoader.hide();
            divDnsSettings.show();
        },
        error: function () {
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

function updateDnsSettingsDataAndGui(responseJSON) {
    sessionData.info.dnsServerDomain = responseJSON.response.dnsServerDomain;
    sessionData.info.uptimestamp = responseJSON.response.uptimestamp; //update timestamp since server may have restarted during current session

    document.title = responseJSON.response.dnsServerDomain + " - " + "Technitium DNS Server v" + responseJSON.response.version;
    $("#lblAboutVersion").text(responseJSON.response.version);
    $("#lblAboutUptime").text(moment(responseJSON.response.uptimestamp).local().format("lll") + " (" + moment(responseJSON.response.uptimestamp).fromNow() + ")");
    $("#lblDnsServerDomain").text(" - " + responseJSON.response.dnsServerDomain);
}

function loadDnsSettings(responseJSON) {
    //update cluster nodes
    sessionData.info.clusterNodes = responseJSON.response.clusterNodes;
    updateAllClusterNodeDropDowns();

    if ($("#optSettingsClusterNode").val() == "cluster")
        updateClusterNodeDropDown($("#optSettingsClusterNode"), true, "cluster");
    else
        updateClusterNodeDropDown($("#optSettingsClusterNode"), true, responseJSON.response.dnsServerDomain);

    //general
    $("#txtDnsServerDomain").val(responseJSON.response.dnsServerDomain);

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
    $("#chkEnableUdpSocketPool").prop("checked", responseJSON.response.enableUdpSocketPool);
    $("#txtUdpSocketPoolExcludedPorts").prop("disabled", !responseJSON.response.enableUdpSocketPool);
    $("#txtUdpSocketPoolExcludedPorts").val(getArrayAsString(responseJSON.response.socketPoolExcludedPorts));
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

    $("#tableQpmPrefixLimitsIPv4").html("");

    if (responseJSON.response.qpmPrefixLimitsIPv4 != null) {
        for (var i = 0; i < responseJSON.response.qpmPrefixLimitsIPv4.length; i++) {
            addQpmPrefixLimitsIPv4Row(responseJSON.response.qpmPrefixLimitsIPv4[i].prefix, responseJSON.response.qpmPrefixLimitsIPv4[i].udpLimit, responseJSON.response.qpmPrefixLimitsIPv4[i].tcpLimit);
        }
    }

    $("#tableQpmPrefixLimitsIPv6").html("");

    if (responseJSON.response.qpmPrefixLimitsIPv6 != null) {
        for (var i = 0; i < responseJSON.response.qpmPrefixLimitsIPv6.length; i++) {
            addQpmPrefixLimitsIPv6Row(responseJSON.response.qpmPrefixLimitsIPv6[i].prefix, responseJSON.response.qpmPrefixLimitsIPv6[i].udpLimit, responseJSON.response.qpmPrefixLimitsIPv6[i].tcpLimit);
        }
    }

    $("#txtQpmLimitSampleMinutes").val(responseJSON.response.qpmLimitSampleMinutes);
    $("#txtQpmLimitUdpTruncation").val(responseJSON.response.qpmLimitUdpTruncationPercentage);
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

    $("#txtReverseProxyNetworkACL").prop("disabled", !responseJSON.response.enableDnsOverUdpProxy && !responseJSON.response.enableDnsOverTcpProxy && !responseJSON.response.enableDnsOverHttp && !responseJSON.response.enableDnsOverHttps);
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

    $("#txtDnsOverHttpRealIpHeader").prop("disabled", !responseJSON.response.enableDnsOverHttp && !responseJSON.response.enableDnsOverHttps);
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
    var enableLogging;

    switch (responseJSON.response.loggingType.toLowerCase()) {
        case "file":
            $("#rdLoggingTypeFile").prop("checked", true);
            enableLogging = true;
            break;

        case "console":
            $("#rdLoggingTypeConsole").prop("checked", true);
            enableLogging = true;
            break;

        case "fileandconsole":
            $("#rdLoggingTypeFileAndConsole").prop("checked", true);
            enableLogging = true;
            break;

        default:
            $("#rdLoggingTypeNone").prop("checked", true);
            enableLogging = false;
            break;
    }

    $("#chkIgnoreResolverLogs").prop("disabled", !enableLogging);
    $("#chkLogQueries").prop("disabled", !enableLogging);
    $("#chkUseLocalTime").prop("disabled", !enableLogging);
    $("#txtLogFolderPath").prop("disabled", !enableLogging);

    $("#chkIgnoreResolverLogs").prop("checked", responseJSON.response.ignoreResolverLogs);
    $("#chkLogQueries").prop("checked", responseJSON.response.logQueries);
    $("#chkUseLocalTime").prop("checked", responseJSON.response.useLocalTime);
    $("#txtLogFolderPath").val(responseJSON.response.logFolder);
    $("#txtMaxLogFileDays").val(responseJSON.response.maxLogFileDays);

    $("#chkEnableInMemoryStats").prop("checked", responseJSON.response.enableInMemoryStats);
    $("#txtMaxStatFileDays").val(responseJSON.response.maxStatFileDays);
}

function saveDnsSettings(objBtn) {
    var node = $("#optSettingsClusterNode").val();

    var includeClusterParameters = (node == "") || (node == "cluster");
    var includeNodeParameters = (node == "") || !includeClusterParameters;

    var formData = "node=" + encodeURIComponent(node);

    //general
    if (includeNodeParameters) {
        var dnsServerDomain = $("#txtDnsServerDomain").val();

        if ((dnsServerDomain === null) || (dnsServerDomain === "")) {
            showAlert("warning", "Missing!", "Please enter server domain name.");
            $("#txtDnsServerDomain").trigger("focus");
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

        formData += "&dnsServerDomain=" + dnsServerDomain + "&dnsServerLocalEndPoints=" + encodeURIComponent(dnsServerLocalEndPoints) + "&dnsServerIPv4SourceAddresses=" + encodeURIComponent(dnsServerIPv4SourceAddresses) + "&dnsServerIPv6SourceAddresses=" + encodeURIComponent(dnsServerIPv6SourceAddresses)
    }

    if (includeClusterParameters) {
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

        var dnsAppsEnableAutomaticUpdate = $("#chkDnsAppsEnableAutomaticUpdate").prop("checked");

        formData += "&defaultRecordTtl=" + defaultRecordTtl + "&defaultResponsiblePerson=" + encodeURIComponent(defaultResponsiblePerson) + "&useSoaSerialDateScheme=" + useSoaSerialDateScheme + "&minSoaRefresh=" + minSoaRefresh + "&minSoaRetry=" + minSoaRetry + "&zoneTransferAllowedNetworks=" + encodeURIComponent(zoneTransferAllowedNetworks) + "&notifyAllowedNetworks=" + encodeURIComponent(notifyAllowedNetworks) + "&dnsAppsEnableAutomaticUpdate=" + dnsAppsEnableAutomaticUpdate;
    }

    if (includeNodeParameters) {
        var preferIPv6 = $("#chkPreferIPv6").prop("checked");
        var enableUdpSocketPool = $("#chkEnableUdpSocketPool").prop("checked");

        var socketPoolExcludedPorts = cleanTextList($("#txtUdpSocketPoolExcludedPorts").val());
        if ((socketPoolExcludedPorts.length == 0) || (socketPoolExcludedPorts === ","))
            socketPoolExcludedPorts = false;
        else
            $("#txtUdpSocketPoolExcludedPorts").val(socketPoolExcludedPorts.replace(/,/g, "\n") + "\n");

        formData += "&preferIPv6=" + preferIPv6 + "&enableUdpSocketPool=" + enableUdpSocketPool + "&socketPoolExcludedPorts=" + encodeURIComponent(socketPoolExcludedPorts);
    }

    if (includeClusterParameters) {
        var udpPayloadSize = $("#txtEdnsUdpPayloadSize").val();
        var dnssecValidation = $("#chkDnssecValidation").prop("checked");

        var eDnsClientSubnet = $("#chkEDnsClientSubnet").prop("checked");

        var eDnsClientSubnetIPv4PrefixLength = $("#txtEDnsClientSubnetIPv4PrefixLength").val();
        if ((eDnsClientSubnetIPv4PrefixLength == null) || (eDnsClientSubnetIPv4PrefixLength === "")) {
            showAlert("warning", "Missing!", "Please enter EDNS Client Subnet IPv4 prefix length.");
            $("#txtEDnsClientSubnetIPv4PrefixLength").trigger("focus");
            return;
        }

        var eDnsClientSubnetIPv6PrefixLength = $("#txtEDnsClientSubnetIPv6PrefixLength").val();
        if ((eDnsClientSubnetIPv6PrefixLength == null) || (eDnsClientSubnetIPv6PrefixLength === "")) {
            showAlert("warning", "Missing!", "Please enter EDNS Client Subnet IPv6 prefix length.");
            $("#txtEDnsClientSubnetIPv6PrefixLength").trigger("focus");
            return;
        }

        var eDnsClientSubnetIpv4Override = $("#txtEDnsClientSubnetIpv4Override").val();
        var eDnsClientSubnetIpv6Override = $("#txtEDnsClientSubnetIpv6Override").val();

        var qpmPrefixLimitsIPv4 = serializeTableData($("#tableQpmPrefixLimitsIPv4"), 3);
        if (qpmPrefixLimitsIPv4 === false)
            return;

        if (qpmPrefixLimitsIPv4.length === 0)
            qpmPrefixLimitsIPv4 = false;

        var qpmPrefixLimitsIPv6 = serializeTableData($("#tableQpmPrefixLimitsIPv6"), 3);
        if (qpmPrefixLimitsIPv6 === false)
            return;

        if (qpmPrefixLimitsIPv6.length === 0)
            qpmPrefixLimitsIPv6 = false;

        var qpmLimitSampleMinutes = $("#txtQpmLimitSampleMinutes").val();
        if ((qpmLimitSampleMinutes == null) || (qpmLimitSampleMinutes === "")) {
            showAlert("warning", "Missing!", "Please enter Queries Per Minute (QPM) sample value.");
            $("#txtQpmLimitSampleMinutes").trigger("focus");
            return;
        }

        var qpmLimitUdpTruncationPercentage = $("#txtQpmLimitUdpTruncation").val();
        if ((qpmLimitUdpTruncationPercentage == null) || (qpmLimitUdpTruncationPercentage === "")) {
            showAlert("warning", "Missing!", "Please enter Queries Per Minute (QPM) limit UDP truncation percentage value.");
            $("#txtQpmLimitUdpTruncation").trigger("focus");
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
            $("#txtClientTimeout").trigger("focus");
            return;
        }

        var tcpSendTimeout = $("#txtTcpSendTimeout").val();
        if ((tcpSendTimeout == null) || (tcpSendTimeout === "")) {
            showAlert("warning", "Missing!", "Please enter a value for TCP Send Timeout.");
            $("#txtTcpSendTimeout").trigger("focus");
            return;
        }

        var tcpReceiveTimeout = $("#txtTcpReceiveTimeout").val();
        if ((tcpReceiveTimeout == null) || (tcpReceiveTimeout === "")) {
            showAlert("warning", "Missing!", "Please enter a value for TCP Receive Timeout.");
            $("#txtTcpReceiveTimeout").trigger("focus");
            return;
        }

        var quicIdleTimeout = $("#txtQuicIdleTimeout").val();
        if ((quicIdleTimeout == null) || (quicIdleTimeout === "")) {
            showAlert("warning", "Missing!", "Please enter a value for QUIC Idle Timeout.");
            $("#txtQuicIdleTimeout").trigger("focus");
            return;
        }

        var quicMaxInboundStreams = $("#txtQuicMaxInboundStreams").val();
        if ((quicMaxInboundStreams == null) || (quicMaxInboundStreams === "")) {
            showAlert("warning", "Missing!", "Please enter a value for QUIC Max Inbound Streams.");
            $("#txtQuicMaxInboundStreams").trigger("focus");
            return;
        }

        var listenBacklog = $("#txtListenBacklog").val();
        if ((listenBacklog == null) || (listenBacklog === "")) {
            showAlert("warning", "Missing!", "Please enter a value for Listen Backlog.");
            $("#txtListenBacklog").trigger("focus");
            return;
        }

        var maxConcurrentResolutionsPerCore = $("#txtMaxConcurrentResolutionsPerCore").val();
        if ((maxConcurrentResolutionsPerCore == null) || (maxConcurrentResolutionsPerCore === "")) {
            showAlert("warning", "Missing!", "Please enter a value for Max Concurrent Resolutions.");
            $("#txtMaxConcurrentResolutionsPerCore").trigger("focus");
            return;
        }

        formData += "&udpPayloadSize=" + udpPayloadSize + "&dnssecValidation=" + dnssecValidation;
        formData += "&eDnsClientSubnet=" + eDnsClientSubnet + "&eDnsClientSubnetIPv4PrefixLength=" + eDnsClientSubnetIPv4PrefixLength + "&eDnsClientSubnetIPv6PrefixLength=" + eDnsClientSubnetIPv6PrefixLength + "&eDnsClientSubnetIpv4Override=" + encodeURIComponent(eDnsClientSubnetIpv4Override) + "&eDnsClientSubnetIpv6Override=" + encodeURIComponent(eDnsClientSubnetIpv6Override);
        formData += "&qpmPrefixLimitsIPv4=" + encodeURIComponent(qpmPrefixLimitsIPv4) + "&qpmPrefixLimitsIPv6=" + encodeURIComponent(qpmPrefixLimitsIPv6) + "&qpmLimitSampleMinutes=" + qpmLimitSampleMinutes + "&qpmLimitUdpTruncationPercentage=" + qpmLimitUdpTruncationPercentage + "&qpmLimitBypassList=" + encodeURIComponent(qpmLimitBypassList);
        formData += "&clientTimeout=" + clientTimeout + "&tcpSendTimeout=" + tcpSendTimeout + "&tcpReceiveTimeout=" + tcpReceiveTimeout + "&quicIdleTimeout=" + quicIdleTimeout + "&quicMaxInboundStreams=" + quicMaxInboundStreams + "&listenBacklog=" + listenBacklog + "&maxConcurrentResolutionsPerCore=" + maxConcurrentResolutionsPerCore;
    }

    //web service
    if (includeNodeParameters) {
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

        formData += "&webServiceLocalAddresses=" + encodeURIComponent(webServiceLocalAddresses) + "&webServiceHttpPort=" + webServiceHttpPort + "&webServiceEnableTls=" + webServiceEnableTls + "&webServiceEnableHttp3=" + webServiceEnableHttp3 + "&webServiceHttpToTlsRedirect=" + webServiceHttpToTlsRedirect + "&webServiceUseSelfSignedTlsCertificate=" + webServiceUseSelfSignedTlsCertificate + "&webServiceTlsPort=" + webServiceTlsPort + "&webServiceTlsCertificatePath=" + encodeURIComponent(webServiceTlsCertificatePath) + "&webServiceTlsCertificatePassword=" + encodeURIComponent(webServiceTlsCertificatePassword) + "&webServiceRealIpHeader=" + encodeURIComponent(webServiceRealIpHeader);
    }

    //optional protocols
    if (includeNodeParameters) {
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
            $("#txtDnsOverUdpProxyPort").trigger("focus");
            return;
        }

        var dnsOverTcpProxyPort = $("#txtDnsOverTcpProxyPort").val();
        if ((dnsOverTcpProxyPort == null) || (dnsOverTcpProxyPort === "")) {
            showAlert("warning", "Missing!", "Please enter a value for DNS-over-TCP-PROXY Port.");
            $("#txtDnsOverTcpProxyPort").trigger("focus");
            return;
        }

        var dnsOverHttpPort = $("#txtDnsOverHttpPort").val();
        if ((dnsOverHttpPort == null) || (dnsOverHttpPort === "")) {
            showAlert("warning", "Missing!", "Please enter a value for DNS-over-HTTP Port.");
            $("#txtDnsOverHttpPort").trigger("focus");
            return;
        }

        var dnsOverTlsPort = $("#txtDnsOverTlsPort").val();
        if ((dnsOverTlsPort == null) || (dnsOverTlsPort === "")) {
            showAlert("warning", "Missing!", "Please enter a value for DNS-over-TLS Port.");
            $("#txtDnsOverTlsPort").trigger("focus");
            return;
        }

        var dnsOverHttpsPort = $("#txtDnsOverHttpsPort").val();
        if ((dnsOverHttpsPort == null) || (dnsOverHttpsPort === "")) {
            showAlert("warning", "Missing!", "Please enter a value for DNS-over-HTTPS Port.");
            $("#txtDnsOverHttpsPort").trigger("focus");
            return;
        }

        var dnsOverQuicPort = $("#txtDnsOverQuicPort").val();
        if ((dnsOverQuicPort == null) || (dnsOverQuicPort === "")) {
            showAlert("warning", "Missing!", "Please enter a value for DNS-over-QUIC Port.");
            $("#txtDnsOverQuicPort").trigger("focus");
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

        formData += "&enableDnsOverUdpProxy=" + enableDnsOverUdpProxy + "&enableDnsOverTcpProxy=" + enableDnsOverTcpProxy + "&enableDnsOverHttp=" + enableDnsOverHttp + "&enableDnsOverTls=" + enableDnsOverTls + "&enableDnsOverHttps=" + enableDnsOverHttps + "&enableDnsOverHttp3=" + enableDnsOverHttp3 + "&enableDnsOverQuic=" + enableDnsOverQuic + "&dnsOverUdpProxyPort=" + dnsOverUdpProxyPort + "&dnsOverTcpProxyPort=" + dnsOverTcpProxyPort + "&dnsOverHttpPort=" + dnsOverHttpPort + "&dnsOverTlsPort=" + dnsOverTlsPort + "&dnsOverHttpsPort=" + dnsOverHttpsPort + "&dnsOverQuicPort=" + dnsOverQuicPort + "&reverseProxyNetworkACL=" + encodeURIComponent(reverseProxyNetworkACL) + "&dnsTlsCertificatePath=" + encodeURIComponent(dnsTlsCertificatePath) + "&dnsTlsCertificatePassword=" + encodeURIComponent(dnsTlsCertificatePassword) + "&dnsOverHttpRealIpHeader=" + encodeURIComponent(dnsOverHttpRealIpHeader);
    }

    //tsig
    if (includeClusterParameters) {
        var tsigKeys = serializeTableData($("#tableTsigKeys"), 3);
        if (tsigKeys === false)
            return;

        if (tsigKeys.length === 0)
            tsigKeys = false;

        formData += "&tsigKeys=" + encodeURIComponent(tsigKeys);
    }

    //recursion
    if (includeClusterParameters) {
        var recursion = $("input[name=rdRecursion]:checked").val();

        var recursionNetworkACL = cleanTextList($("#txtRecursionNetworkACL").val());

        if ((recursionNetworkACL.length === 0) || (recursionNetworkACL === ","))
            recursionNetworkACL = false;
        else
            $("#txtRecursionNetworkACL").val(recursionNetworkACL.replace(/,/g, "\n"));

        var randomizeName = $("#chkRandomizeName").prop("checked");
        var qnameMinimization = $("#chkQnameMinimization").prop("checked");

        var resolverRetries = $("#txtResolverRetries").val();
        if ((resolverRetries == null) || (resolverRetries === "")) {
            showAlert("warning", "Missing!", "Please enter a value for Resolver Retries.");
            $("#txtResolverRetries").trigger("focus");
            return;
        }

        var resolverTimeout = $("#txtResolverTimeout").val();
        if ((resolverTimeout == null) || (resolverTimeout === "")) {
            showAlert("warning", "Missing!", "Please enter a value for Resolver Timeout.");
            $("#txtResolverTimeout").trigger("focus");
            return;
        }

        var resolverConcurrency = $("#txtResolverConcurrency").val();
        if ((resolverConcurrency == null) || (resolverConcurrency === "")) {
            showAlert("warning", "Missing!", "Please enter a value for Resolver Concurrency.");
            $("#txtResolverConcurrency").trigger("focus");
            return;
        }

        var resolverMaxStackCount = $("#txtResolverMaxStackCount").val();
        if ((resolverMaxStackCount == null) || (resolverMaxStackCount === "")) {
            showAlert("warning", "Missing!", "Please enter a value for Resolver Max Stack Count.");
            $("#txtResolverMaxStackCount").trigger("focus");
            return;
        }

        formData += "&recursion=" + recursion + "&recursionNetworkACL=" + encodeURIComponent(recursionNetworkACL) + "&randomizeName=" + randomizeName + "&qnameMinimization=" + qnameMinimization + "&resolverRetries=" + resolverRetries + "&resolverTimeout=" + resolverTimeout + "&resolverConcurrency=" + resolverConcurrency + "&resolverMaxStackCount=" + resolverMaxStackCount;
    }

    //cache
    if (includeNodeParameters) {
        var saveCache = $("#chkSaveCache").prop("checked");

        var serveStale = $("#chkServeStale").prop("checked");
        var serveStaleTtl = $("#txtServeStaleTtl").val();
        var serveStaleAnswerTtl = $("#txtServeStaleAnswerTtl").val();
        var serveStaleResetTtl = $("#txtServeStaleResetTtl").val();
        var serveStaleMaxWaitTime = $("#txtServeStaleMaxWaitTime").val();

        var cacheMaximumEntries = $("#txtCacheMaximumEntries").val();
        if ((cacheMaximumEntries === null) || (cacheMaximumEntries === "")) {
            showAlert("warning", "Missing!", "Please enter cache maximum entries value.");
            $("#txtCacheMaximumEntries").trigger("focus");
            return;
        }

        var cacheMinimumRecordTtl = $("#txtCacheMinimumRecordTtl").val();
        if ((cacheMinimumRecordTtl === null) || (cacheMinimumRecordTtl === "")) {
            showAlert("warning", "Missing!", "Please enter cache minimum record TTL value.");
            $("#txtCacheMinimumRecordTtl").trigger("focus");
            return;
        }

        var cacheMaximumRecordTtl = $("#txtCacheMaximumRecordTtl").val();
        if ((cacheMaximumRecordTtl === null) || (cacheMaximumRecordTtl === "")) {
            showAlert("warning", "Missing!", "Please enter cache maximum record TTL value.");
            $("#txtCacheMaximumRecordTtl").trigger("focus");
            return;
        }

        var cacheNegativeRecordTtl = $("#txtCacheNegativeRecordTtl").val();
        if ((cacheNegativeRecordTtl === null) || (cacheNegativeRecordTtl === "")) {
            showAlert("warning", "Missing!", "Please enter cache negative record TTL value.");
            $("#txtCacheNegativeRecordTtl").trigger("focus");
            return;
        }

        var cacheFailureRecordTtl = $("#txtCacheFailureRecordTtl").val();
        if ((cacheFailureRecordTtl === null) || (cacheFailureRecordTtl === "")) {
            showAlert("warning", "Missing!", "Please enter cache failure record TTL value.");
            $("#txtCacheFailureRecordTtl").trigger("focus");
            return;
        }

        var cachePrefetchEligibility = $("#txtCachePrefetchEligibility").val();
        if ((cachePrefetchEligibility === null) || (cachePrefetchEligibility === "")) {
            showAlert("warning", "Missing!", "Please enter cache prefetch eligibility value.");
            $("#txtCachePrefetchEligibility").trigger("focus");
            return;
        }

        var cachePrefetchTrigger = $("#txtCachePrefetchTrigger").val();
        if ((cachePrefetchTrigger === null) || (cachePrefetchTrigger === "")) {
            showAlert("warning", "Missing!", "Please enter cache prefetch trigger value.");
            $("#txtCachePrefetchTrigger").trigger("focus");
            return;
        }

        var cachePrefetchSampleIntervalInMinutes = $("#txtCachePrefetchSampleIntervalInMinutes").val();
        if ((cachePrefetchSampleIntervalInMinutes === null) || (cachePrefetchSampleIntervalInMinutes === "")) {
            showAlert("warning", "Missing!", "Please enter cache auto prefetch sample interval value.");
            $("#txtCachePrefetchSampleIntervalInMinutes").trigger("focus");
            return;
        }

        var cachePrefetchSampleEligibilityHitsPerHour = $("#txtCachePrefetchSampleEligibilityHitsPerHour").val();
        if ((cachePrefetchSampleEligibilityHitsPerHour === null) || (cachePrefetchSampleEligibilityHitsPerHour === "")) {
            showAlert("warning", "Missing!", "Please enter cache auto prefetch sample eligibility value.");
            $("#txtCachePrefetchSampleEligibilityHitsPerHour").trigger("focus");
            return;
        }

        formData += "&saveCache=" + saveCache + "&serveStale=" + serveStale + "&serveStaleTtl=" + serveStaleTtl + "&serveStaleAnswerTtl=" + serveStaleAnswerTtl + "&serveStaleResetTtl=" + serveStaleResetTtl + "&serveStaleMaxWaitTime=" + serveStaleMaxWaitTime + "&cacheMaximumEntries=" + cacheMaximumEntries + "&cacheMinimumRecordTtl=" + cacheMinimumRecordTtl + "&cacheMaximumRecordTtl=" + cacheMaximumRecordTtl + "&cacheNegativeRecordTtl=" + cacheNegativeRecordTtl + "&cacheFailureRecordTtl=" + cacheFailureRecordTtl + "&cachePrefetchEligibility=" + cachePrefetchEligibility + "&cachePrefetchTrigger=" + cachePrefetchTrigger + "&cachePrefetchSampleIntervalInMinutes=" + cachePrefetchSampleIntervalInMinutes + "&cachePrefetchSampleEligibilityHitsPerHour=" + cachePrefetchSampleEligibilityHitsPerHour;
    }

    //blocking
    if (includeClusterParameters) {
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

        formData += "&enableBlocking=" + enableBlocking + "&allowTxtBlockingReport=" + allowTxtBlockingReport + "&blockingBypassList=" + encodeURIComponent(blockingBypassList) + "&blockingType=" + blockingType + "&customBlockingAddresses=" + encodeURIComponent(customBlockingAddresses) + "&blockingAnswerTtl=" + blockingAnswerTtl + "&blockListUrls=" + encodeURIComponent(blockListUrls) + "&blockListUpdateIntervalHours=" + blockListUpdateIntervalHours;
    }

    //proxy & forwarders
    if (includeClusterParameters) {
        var proxy;

        var proxyType = $("input[name=rdProxyType]:checked").val().toLowerCase();
        if (proxyType === "none") {
            proxy = "&proxyType=" + proxyType;
        }
        else {
            var proxyAddress = $("#txtProxyAddress").val();

            if ((proxyAddress === null) || (proxyAddress === "")) {
                showAlert("warning", "Missing!", "Please enter proxy server address.");
                $("#txtProxyAddress").trigger("focus");
                return;
            }

            var proxyPort = $("#txtProxyPort").val();

            if ((proxyPort === null) || (proxyPort === "")) {
                showAlert("warning", "Missing!", "Please enter proxy server port.");
                $("#txtProxyPort").trigger("focus");
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

        var forwarderProtocol = $("input[name=rdForwarderProtocol]:checked").val();

        var concurrentForwarding = $("#chkEnableConcurrentForwarding").prop("checked");

        var forwarderRetries = $("#txtForwarderRetries").val();
        if ((forwarderRetries == null) || (forwarderRetries === "")) {
            showAlert("warning", "Missing!", "Please enter a value for Forwarder Retries.");
            $("#txtForwarderRetries").trigger("focus");
            return;
        }

        var forwarderTimeout = $("#txtForwarderTimeout").val();
        if ((forwarderTimeout == null) || (forwarderTimeout === "")) {
            showAlert("warning", "Missing!", "Please enter a value for Forwarder Timeout.");
            $("#txtForwarderTimeout").trigger("focus");
            return;
        }

        var forwarderConcurrency = $("#txtForwarderConcurrency").val();
        if ((forwarderConcurrency == null) || (forwarderConcurrency === "")) {
            showAlert("warning", "Missing!", "Please enter a value for Forwarder Concurrency.");
            $("#txtForwarderConcurrency").trigger("focus");
            return;
        }

        formData += proxy + "&forwarders=" + encodeURIComponent(forwarders) + "&forwarderProtocol=" + forwarderProtocol + "&concurrentForwarding=" + concurrentForwarding + "&forwarderRetries=" + forwarderRetries + "&forwarderTimeout=" + forwarderTimeout + "&forwarderConcurrency=" + forwarderConcurrency;
    }

    //logging
    if (includeNodeParameters) {
        var loggingType = $("input[name=rdLoggingType]:checked").val();
        var ignoreResolverLogs = $("#chkIgnoreResolverLogs").prop("checked");
        var logQueries = $("#chkLogQueries").prop("checked");
        var useLocalTime = $("#chkUseLocalTime").prop("checked");
        var logFolder = $("#txtLogFolderPath").val();
        var maxLogFileDays = $("#txtMaxLogFileDays").val();

        var enableInMemoryStats = $("#chkEnableInMemoryStats").prop("checked");
        var maxStatFileDays = $("#txtMaxStatFileDays").val();

        formData += "&loggingType=" + loggingType + "&ignoreResolverLogs=" + ignoreResolverLogs + "&logQueries=" + logQueries + "&useLocalTime=" + useLocalTime + "&logFolder=" + encodeURIComponent(logFolder) + "&maxLogFileDays=" + maxLogFileDays + "&enableInMemoryStats=" + enableInMemoryStats + "&maxStatFileDays=" + maxStatFileDays;
    }

    //send request
    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/settings/set?token=" + sessionData.token,
        method: "POST",
        data: formData,
        processData: false,
        showInnerError: true,
        success: function (responseJSON) {
            if ((node == "") || (node == sessionData.info.dnsServerDomain))
                updateDnsSettingsDataAndGui(responseJSON);

            loadDnsSettings(responseJSON);

            btn.button("reset");
            showAlert("success", "Settings Saved!", "DNS Server settings were saved successfully.");

            if (sessionData.info.dnsServerDomain == responseJSON.server)
                checkForWebConsoleRedirection(responseJSON);
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        }
    });
}

function addQpmPrefixLimitsIPv4Row(prefix, udpLimit, tcpLimit) {
    var id = Math.floor(Math.random() * 10000);

    var tableHtmlRows = "<tr id=\"tableQpmPrefixLimitsIPv4Row" + id + "\"><td><input type=\"number\" class=\"form-control\" value=\"" + htmlEncode(prefix) + "\"></td>";
    tableHtmlRows += "<td><input type=\"number\" class=\"form-control\" value=\"" + htmlEncode(udpLimit) + "\"></td>";
    tableHtmlRows += "<td><input type=\"number\" class=\"form-control\" value=\"" + htmlEncode(tcpLimit) + "\"></td>";

    tableHtmlRows += "<td><button type=\"button\" class=\"btn btn-danger\" onclick=\"$('#tableQpmPrefixLimitsIPv4Row" + id + "').remove();\">Delete</button></td></tr>";

    $("#tableQpmPrefixLimitsIPv4").append(tableHtmlRows);
}

function addQpmPrefixLimitsIPv6Row(prefix, udpLimit, tcpLimit) {
    var id = Math.floor(Math.random() * 10000);

    var tableHtmlRows = "<tr id=\"tableQpmPrefixLimitsIPv6Row" + id + "\"><td><input type=\"number\" class=\"form-control\" value=\"" + htmlEncode(prefix) + "\"></td>";
    tableHtmlRows += "<td><input type=\"number\" class=\"form-control\" value=\"" + htmlEncode(udpLimit) + "\"></td>";
    tableHtmlRows += "<td><input type=\"number\" class=\"form-control\" value=\"" + htmlEncode(tcpLimit) + "\"></td>";

    tableHtmlRows += "<td><button type=\"button\" class=\"btn btn-danger\" onclick=\"$('#tableQpmPrefixLimitsIPv6Row" + id + "').remove();\">Delete</button></td></tr>";

    $("#tableQpmPrefixLimitsIPv6").append(tableHtmlRows);
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

    var btn = $("#btnUpdateBlockListsNow");
    btn.button("loading");

    HTTPRequest({
        url: "api/settings/forceUpdateBlockLists?token=" + sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");

            $("#lblBlockListNextUpdatedOn").text("Updating Now");

            showAlert("success", "Updating Block List!", "Block list update was triggered successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        }
    });
}

function temporaryDisableBlockingNow() {
    var minutes = $("#txtTemporaryDisableBlockingMinutes").val();

    if ((minutes === null) || (minutes === "")) {
        showAlert("warning", "Missing!", "Please enter a value in minutes to temporarily disable blocking.");
        $("#txtTemporaryDisableBlockingMinutes").trigger("focus");
        return;
    }

    if (!confirm("Are you sure to temporarily disable blocking for " + minutes + " minute(s)?"))
        return;

    var btn = $("#btnTemporaryDisableBlockingNow");
    btn.button("loading");

    HTTPRequest({
        url: "api/settings/temporaryDisableBlocking?token=" + sessionData.token + "&minutes=" + minutes,
        success: function (responseJSON) {
            btn.button("reset");

            $("#chkEnableBlocking").prop("checked", false);
            $("#lblTemporaryDisableBlockingTill").text(moment(responseJSON.response.temporaryDisableBlockingTill).local().format("YYYY-MM-DD HH:mm:ss"));
            updateBlockingState();

            showAlert("success", "Blocking Disabled!", "Blocking was successfully disabled temporarily for " + htmlEncode(minutes) + " minute(s).");

            setTimeout(updateBlockingState, 500);
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
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

    var type = $("input[name=rdStatType]:checked").val();
    var custom = "";

    if (type === "custom") {
        var txtStart = $("#dpCustomDayWiseStart").val();
        if (txtStart === null || (txtStart === "")) {
            showAlert("warning", "Missing!", "Please select a start date.");
            $("#dpCustomDayWiseStart").trigger("focus");
            return;
        }

        var txtEnd = $("#dpCustomDayWiseEnd").val();
        if (txtEnd === null || (txtEnd === "")) {
            showAlert("warning", "Missing!", "Please select an end date.");
            $("#dpCustomDayWiseEnd").trigger("focus");
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

    var node = $("#optDashboardClusterNode").val();

    if (!hideLoader) {
        divDashboard.hide();
        divDashboardLoader.show();
    }

    HTTPRequest({
        url: "api/dashboard/stats/get?token=" + sessionData.token + "&type=" + type + "&utc=true" + custom + "&node=" + encodeURIComponent(node),
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
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"queryDnsServer('" + topDomains[i].name + "', null, '" + node + "'); return false;\">Query DNS Server</a></li>";
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
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"queryDnsServer('" + topBlockedDomains[i].name + "', null, '" + node + "'); return false;\">Query DNS Server</a></li>";
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

    var type = $("input[name=rdStatType]:checked").val();
    var custom = "";

    if (type === "custom") {
        var txtStart = $("#dpCustomDayWiseStart").val();
        if (txtStart === null || (txtStart === "")) {
            showAlert("warning", "Missing!", "Please select a start date.");
            $("#dpCustomDayWiseStart").trigger("focus");
            return;
        }

        var txtEnd = $("#dpCustomDayWiseEnd").val();
        if (txtEnd === null || (txtEnd === "")) {
            showAlert("warning", "Missing!", "Please select an end date.");
            $("#dpCustomDayWiseEnd").trigger("focus");
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

    var node = $("#optDashboardClusterNode").val();

    HTTPRequest({
        url: "api/dashboard/stats/getTop?token=" + sessionData.token + "&type=" + type + custom + "&statsType=" + statsType + "&limit=" + limit + "&node=" + encodeURIComponent(node),
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
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"queryDnsServer('" + topDomains[i].name + "', null, '" + node + "'); return false;\">Query DNS Server</a></li>";
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
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"queryDnsServer('" + topBlockedDomains[i].name + "', null, '" + node + "'); return false;\">Query DNS Server</a></li>";
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

function resetBackupSettingsModal() {
    $("#divBackupSettingsAlert").html("");

    $("#chkBackupAuthConfig").prop("checked", true);
    $("#chkBackupClusterConfig").prop("checked", true);
    $("#chkBackupWebServiceConfig").prop("checked", true);
    $("#chkBackupDnsConfig").prop("checked", true);
    $("#chkBackupLogConfig").prop("checked", true);
    $("#chkBackupZones").prop("checked", true);
    $("#chkBackupAllowedZones").prop("checked", true);
    $("#chkBackupBlockedZones").prop("checked", true);
    $("#chkBackupBlockLists").prop("checked", true);
    $("#chkBackupApps").prop("checked", true);
    $("#chkBackupScopes").prop("checked", true);
    $("#chkBackupStats").prop("checked", true);
    $("#chkBackupLogs").prop("checked", false);
}

function backupSettings() {
    var divBackupSettingsAlert = $("#divBackupSettingsAlert");

    var authConfig = $("#chkBackupAuthConfig").prop("checked");
    var clusterConfig = $("#chkBackupClusterConfig").prop("checked");
    var webServiceSettings = $("#chkBackupWebServiceConfig").prop("checked");
    var dnsSettings = $("#chkBackupDnsConfig").prop("checked");
    var logSettings = $("#chkBackupLogConfig").prop("checked");
    var zones = $("#chkBackupZones").prop("checked");
    var allowedZones = $("#chkBackupAllowedZones").prop("checked");
    var blockedZones = $("#chkBackupBlockedZones").prop("checked");
    var blockLists = $("#chkBackupBlockLists").prop("checked");
    var apps = $("#chkBackupApps").prop("checked");
    var scopes = $("#chkBackupScopes").prop("checked");
    var stats = $("#chkBackupStats").prop("checked");
    var logs = $("#chkBackupLogs").prop("checked");

    if (!authConfig && !clusterConfig && !webServiceSettings && !dnsSettings && !logSettings && !zones && !allowedZones && !blockedZones && !blockLists && !apps && !scopes && !stats && !logs) {
        showAlert("warning", "Missing!", "Please select at least one item to backup.", divBackupSettingsAlert);
        return;
    }

    var node = $("#optSettingsClusterNode").val();

    window.open("api/settings/backup?token=" + sessionData.token + "&authConfig=" + authConfig + "&clusterConfig=" + clusterConfig + "&webServiceSettings=" + webServiceSettings + "&dnsSettings=" + dnsSettings + "&logSettings=" + logSettings + "&zones=" + zones + "&allowedZones=" + allowedZones + "&blockedZones=" + blockedZones + "&blockLists=" + blockLists + "&apps=" + apps + "&scopes=" + scopes + "&stats=" + stats + "&logs=" + logs + "&node=" + encodeURIComponent(node) + "&ts=" + (new Date().getTime()), "_blank");

    $("#modalBackupSettings").modal("hide");
    showAlert("success", "Backed Up!", "Settings were backed up successfully.");
}

function resetRestoreSettingsModal() {
    $("#divRestoreSettingsAlert").html("");

    $("#fileBackupZip").val("");

    $("#chkRestoreAuthConfig").prop("checked", true);
    $("#chkRestoreClusterConfig").prop("checked", true);
    $("#chkRestoreWebServiceConfig").prop("checked", true);
    $("#chkRestoreDnsConfig").prop("checked", true);
    $("#chkRestoreLogConfig").prop("checked", true);
    $("#chkRestoreZones").prop("checked", true);
    $("#chkRestoreAllowedZones").prop("checked", true);
    $("#chkRestoreBlockedZones").prop("checked", true);
    $("#chkRestoreBlockLists").prop("checked", true);
    $("#chkRestoreApps").prop("checked", true);
    $("#chkRestoreScopes").prop("checked", true);
    $("#chkRestoreStats").prop("checked", true);
    $("#chkRestoreLogs").prop("checked", false);
    $("#chkDeleteExistingFiles").prop("checked", true);
}

function restoreSettings() {
    var divRestoreSettingsAlert = $("#divRestoreSettingsAlert");

    var fileBackupZip = $("#fileBackupZip");

    if (fileBackupZip[0].files.length === 0) {
        showAlert("warning", "Missing!", "Please select a backup zip file to restore.", divRestoreSettingsAlert);
        fileBackupZip.trigger("focus");
        return;
    }

    var authConfig = $("#chkRestoreAuthConfig").prop("checked");
    var clusterConfig = $("#chkRestoreClusterConfig").prop("checked");
    var webServiceSettings = $("#chkRestoreWebServiceConfig").prop("checked");
    var dnsSettings = $("#chkRestoreDnsConfig").prop("checked");
    var logSettings = $("#chkRestoreLogConfig").prop("checked");
    var zones = $("#chkRestoreZones").prop("checked");
    var allowedZones = $("#chkRestoreAllowedZones").prop("checked");
    var blockedZones = $("#chkRestoreBlockedZones").prop("checked");
    var blockLists = $("#chkRestoreBlockLists").prop("checked");
    var apps = $("#chkRestoreApps").prop("checked");
    var scopes = $("#chkRestoreScopes").prop("checked");
    var stats = $("#chkRestoreStats").prop("checked");
    var logs = $("#chkRestoreLogs").prop("checked");

    var deleteExistingFiles = $("#chkDeleteExistingFiles").prop("checked");

    if (!authConfig && !clusterConfig && !webServiceSettings && !dnsSettings && !logSettings && !zones && !allowedZones && !blockedZones && !blockLists && !apps && !scopes && !stats && !logs) {
        showAlert("warning", "Missing!", "Please select at least one item to restore.", divRestoreSettingsAlert);
        return;
    }

    var formData = new FormData();
    formData.append("fileBackupZip", $("#fileBackupZip")[0].files[0]);

    var node = $("#optSettingsClusterNode").val();

    var btn = $("#btnRestoreSettings");
    btn.button("loading");

    HTTPRequest({
        url: "api/settings/restore?token=" + sessionData.token + "&authConfig=" + authConfig + "&clusterConfig=" + clusterConfig + "&webServiceSettings=" + webServiceSettings + "&dnsSettings=" + dnsSettings + "&logSettings=" + logSettings + "&zones=" + zones + "&allowedZones=" + allowedZones + "&blockedZones=" + blockedZones + "&blockLists=" + blockLists + "&apps=" + apps + "&scopes=" + scopes + "&stats=" + stats + "&logs=" + logs + "&deleteExistingFiles=" + deleteExistingFiles + "&node=" + encodeURIComponent(node),
        method: "POST",
        data: formData,
        contentType: false,
        processData: false,
        success: function (responseJSON) {
            if ((node == "") || (node == sessionData.info.dnsServerDomain))
                updateDnsSettingsDataAndGui(responseJSON);

            loadDnsSettings(responseJSON);

            $("#modalRestoreSettings").modal("hide");
            btn.button("reset");

            showAlert("success", "Restored!", "Settings were restored successfully.");

            if (sessionData.info.dnsServerDomain == responseJSON.server)
                checkForWebConsoleRedirection(responseJSON);
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        },
        objAlertPlaceholder: divRestoreSettingsAlert
    });
}
