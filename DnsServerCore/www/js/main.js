/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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
var autoRefreshTimer = null;
var autoRefreshInterval = 10000;
var autoRefreshFastPollCount = 0;
var lastMetricsPollTime = 0;
var lastMetricsTotalQueries = -1;
var isPollingDashboard = false;
var isDashboardTabActive = true;
window.chartDashboardMain = null;
window.chartDashboardCache = null;
window.chartDashboardClients = null;
window.chartDashboardBlocked = null;
window.chartDashboardHealth = null;
var reverseProxyDetected = false;
var quickBlockLists = null;
var quickForwardersList = null;

function showPageLogin(autoLogin) {
    hideAlert();

    localStorage.removeItem("token");

    $("#header").hide();
    $("#pageMain").hide();
    $("#mnuUser").hide();
    $("#appShell").hide();
    $("#appSidebar").hide();
    $("#appTopBar").hide();

    $("#txtUser").val("");
    $("#txtPass").val("");
    $("#txtPass").prop("disabled", false);
    $("#div2FAOTP").hide();
    $("#txt2FATOTP").val("");
    $("#btnLogin").button("reset");
    $("#pageLogin").css("display", "flex").show();

    $("#txtUser").trigger("focus");

    if (refreshTimerHandle != null) {
        clearInterval(refreshTimerHandle);
        refreshTimerHandle = null;
    }
    stopAutoRefreshTimer();

    HTTPRequest({
        url: "api/status",
        success: function (responseJSON) {
            if (responseJSON.ssoEnabled)
                $("#divLoginSso").show();
            else
                $("#divLoginSso").hide();

            if (autoLogin && responseJSON.hasDefaultCredentials)
                login("admin", "admin");
        }
    });
}

function showPageMain() {
    hideAlert();

    $("#txtUser").val("");
    $("#txtPass").val("");
    $("#txt2FATOTP").val("");

    $("#pageLogin").hide();
    $("#pageMain").show();

    switch (sessionData.type) {
        case "RemoteSSO":
            $("#mnuUserChangePassword").hide();
            $("#mnuUserConfigure2FA").hide();
            $("#mnuSidebarChangePassword").hide();
            $("#mnuSidebarConfigure2FA").hide();
            $("#mnuTopbarChangePassword").hide();
            $("#mnuTopbarConfigure2FA").hide();
            break;

        case "RemoteLDAP":
            $("#mnuUserChangePassword").hide();
            $("#mnuUserConfigure2FA").show();
            $("#mnuSidebarChangePassword").hide();
            $("#mnuSidebarConfigure2FA").show();
            $("#mnuTopbarChangePassword").hide();
            $("#mnuTopbarConfigure2FA").show();
            break;

        case "Local":
        default:
            $("#mnuUserChangePassword").show();
            $("#mnuUserConfigure2FA").show();
            $("#mnuSidebarChangePassword").show();
            $("#mnuSidebarConfigure2FA").show();
            $("#mnuTopbarChangePassword").show();
            $("#mnuTopbarConfigure2FA").show();
            break;
    }

    $("#pageLogin").hide();
    $("#mnuUser").show();

    const currentLayout = localStorage.getItem("technitium_layout") || "modern";
    if (currentLayout === "classic") {
        $("#header").show();
        $("#appSidebar").hide();
        $("#appTopBar").hide();
        $("#appShell").show();
    } else {
        $("#header").hide();
        $("#appShell").css("display", "flex").show();
        $("#appSidebar").show();
        $("#appTopBar").show();
    }

    if (localStorage.getItem("sidebar_collapsed") === "true") {
        $("#appSidebar").addClass("collapsed");
        $("#iconSidebarCollapse").attr("class", "fa fa-chevron-right");
    } else {
        $("#iconSidebarCollapse").attr("class", "fa fa-chevron-left");
    }

    if (typeof sessionData !== "undefined" && sessionData && sessionData.displayName) {
        $("#lblSidebarUserName").text(sessionData.displayName);
        $("#lblSidebarUserMenuHeader").text(sessionData.displayName);
        $("#lblTopbarUserName").text(sessionData.displayName);
        $("#mnuUserDisplayName").text(sessionData.displayName);
    }

    if (typeof sessionData !== "undefined" && sessionData && sessionData.info) {
        if (sessionData.info.dnsServerDomain) {
            $("#lblDnsServerDomainModern").text("• " + sessionData.info.dnsServerDomain);
        }
        if (sessionData.info.version) {
            $("#lblFooterVersion").text("v" + sessionData.info.version);
        }
        // Sync Permissions to Sidebar Items defensively
        if (sessionData.info.permissions) {
            var perms = sessionData.info.permissions;
            if (perms.Dashboard && perms.Dashboard.canView === false) $("#sidebarNavItemDashboard").hide(); else $("#sidebarNavItemDashboard").show();
            if (perms.Zones && perms.Zones.canView === false) $("#sidebarNavItemZones").hide(); else $("#sidebarNavItemZones").show();
            if (perms.Cache && perms.Cache.canView === false) $("#sidebarNavItemCachedZones").hide(); else $("#sidebarNavItemCachedZones").show();
            if (perms.Allowed && perms.Allowed.canView === false) $("#sidebarNavItemAllowedZones").hide(); else $("#sidebarNavItemAllowedZones").show();
            if (perms.Blocked && perms.Blocked.canView === false) $("#sidebarNavItemBlockedZones").hide(); else $("#sidebarNavItemBlockedZones").show();
            if (perms.Apps && perms.Apps.canView === false) $("#sidebarNavItemApps").hide(); else $("#sidebarNavItemApps").show();
            if (perms.DnsClient && perms.DnsClient.canView === false) $("#sidebarNavItemDnsClient").hide(); else $("#sidebarNavItemDnsClient").show();
            if (perms.Settings && perms.Settings.canView === false) $("#sidebarNavItemSettings").hide(); else $("#sidebarNavItemSettings").show();
            var dhcpPerm = perms.DhcpServer || perms.Dhcp;
            if (dhcpPerm && dhcpPerm.canView === false) $("#sidebarNavItemDhcp").hide(); else $("#sidebarNavItemDhcp").show();
            var adminPerm = perms.Administration || perms.Admin;
            if (adminPerm && adminPerm.canView === false) $("#sidebarNavItemAdmin").hide(); else $("#sidebarNavItemAdmin").show();
            if (perms.Logs && perms.Logs.canView === false) $("#sidebarNavItemLogs").hide(); else $("#sidebarNavItemLogs").show();
        }
    }

    $(".sidebar-nav-item").removeClass("active");
    $("#sidebarNavItemDashboard").addClass("active");
    updateAppBreadcrumbs("Dashboard");

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

    $("#txtZonesFilterName").val("");
    $("#optZonesFilterType").val("");
    $("#tableZonesBody").html("");
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
        startAutoRefreshTimer();
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
    initTheme();
    initLayout();
    initUpdateNotificationMenu();

    var headerHtml = $("#header").html();

    $("#header").html("<div class=\"title\"><a href=\".\"><img src=\"img/logo25x25.png\" alt=\"Technitium Logo\" /><span class=\"text\" style=\"color: #ffffff;\">Technitium</span></a>" + headerHtml + "</div>");
    $("#footer").html("<div class=\"content\"><a href=\"https://technitium.com/\" target=\"_blank\">Technitium</a> | <a href=\"https://blog.technitium.com/\" target=\"_blank\">Blog</a> | <a href=\"https://go.technitium.com/?id=35\" target=\"_blank\">Donate</a> | <a href=\"https://dnsclient.net/\" target=\"_blank\">DNS Client</a> | <a href=\"https://github.com/TechnitiumSoftware/DnsServer\" target=\"_blank\"><i class=\"fa fa-github\"></i>&nbsp;GitHub</a> | <a href=\"#\" onclick=\"showAbout(); return false;\">About</a></div>");

    // Dynamic Server Domain Sync for Modern Topbar Breadcrumbs
    var lblDomainElem = document.getElementById("lblDnsServerDomain");
    if (lblDomainElem) {
        var domainObserver = new MutationObserver(function () {
            var domainText = $("#lblDnsServerDomain").text();
            if (domainText) {
                domainText = domainText.replace(/^[\s\-•]+/, "").trim();
                if (domainText) {
                    $("#lblDnsServerDomainModern").text("• " + domainText).show();
                } else {
                    $("#lblDnsServerDomainModern").text("").hide();
                }
            } else {
                $("#lblDnsServerDomainModern").text("").hide();
            }
        });
        domainObserver.observe(lblDomainElem, { childList: true, characterData: true, subtree: true });
    }

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

    $("#chkWebServiceEnableHttpUnixSocket").on("click", function () {
        var webServiceEnableHttpUnixSocket = $("#chkWebServiceEnableHttpUnixSocket").prop("checked");
        $("#txtWebServiceHttpUnixSocket").prop("disabled", !webServiceEnableHttpUnixSocket);
    });

    $("#chkWebServiceEnableTlsUnixSocket").on("click", function () {
        var webServiceEnableTlsUnixSocket = $("#chkWebServiceEnableTlsUnixSocket").prop("checked");
        var webServiceEnableTls = $("#chkWebServiceEnableTls").prop("checked");

        $("#txtWebServiceTlsUnixSocket").prop("disabled", !webServiceEnableTlsUnixSocket);
        $("#chkWebServiceUseSelfSignedTlsCertificate").prop("disabled", !webServiceEnableTls && !webServiceEnableTlsUnixSocket);
        $("#txtWebServiceTlsCertificatePath").prop("disabled", !webServiceEnableTls && !webServiceEnableTlsUnixSocket);
        $("#txtWebServiceTlsCertificatePassword").prop("disabled", !webServiceEnableTls && !webServiceEnableTlsUnixSocket);
    });

    $("#chkWebServiceEnableTls").on("click", function () {
        var webServiceEnableTlsUnixSocket = $("#chkWebServiceEnableTlsUnixSocket").prop("checked");
        var webServiceEnableTls = $("#chkWebServiceEnableTls").prop("checked");

        $("#chkWebServiceEnableHttp3").prop("disabled", !webServiceEnableTls);
        $("#chkWebServiceHttpToTlsRedirect").prop("disabled", !webServiceEnableTls);
        $("#chkWebServiceUseSelfSignedTlsCertificate").prop("disabled", !webServiceEnableTls && !webServiceEnableTlsUnixSocket);
        $("#txtWebServiceTlsPort").prop("disabled", !webServiceEnableTls);
        $("#txtWebServiceTlsCertificatePath").prop("disabled", !webServiceEnableTls && !webServiceEnableTlsUnixSocket);
        $("#txtWebServiceTlsCertificatePassword").prop("disabled", !webServiceEnableTls && !webServiceEnableTlsUnixSocket);
    });

    $("#chkEnableEDnsClientSubnetSourceAddress").on("click", function () {
        var chkEnableEDnsClientSubnetSourceAddress = $("#chkEnableEDnsClientSubnetSourceAddress").prop("checked");
        var enableDnsOverUdpProxy = $("#chkEnableDnsOverUdpProxy").prop("checked");
        var enableDnsOverTcpProxy = $("#chkEnableDnsOverTcpProxy").prop("checked");
        var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");

        $("#txtDnsOverUdpProxyPort").prop("disabled", !enableDnsOverUdpProxy);
        $("#txtDnsReverseProxyNetworkACL").prop("disabled", !chkEnableEDnsClientSubnetSourceAddress && !enableDnsOverUdpProxy && !enableDnsOverTcpProxy && !enableDnsOverHttp && !enableDnsOverHttps);
    });

    $("#chkEnableDnsOverUdpProxy").on("click", function () {
        var chkEnableEDnsClientSubnetSourceAddress = $("#chkEnableEDnsClientSubnetSourceAddress").prop("checked");
        var enableDnsOverUdpProxy = $("#chkEnableDnsOverUdpProxy").prop("checked");
        var enableDnsOverTcpProxy = $("#chkEnableDnsOverTcpProxy").prop("checked");
        var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");

        $("#txtDnsOverUdpProxyPort").prop("disabled", !enableDnsOverUdpProxy);
        $("#txtDnsReverseProxyNetworkACL").prop("disabled", !chkEnableEDnsClientSubnetSourceAddress && !enableDnsOverUdpProxy && !enableDnsOverTcpProxy && !enableDnsOverHttp && !enableDnsOverHttps);
    });

    $("#chkEnableDnsOverTcpProxy").on("click", function () {
        var chkEnableEDnsClientSubnetSourceAddress = $("#chkEnableEDnsClientSubnetSourceAddress").prop("checked");
        var enableDnsOverUdpProxy = $("#chkEnableDnsOverUdpProxy").prop("checked");
        var enableDnsOverTcpProxy = $("#chkEnableDnsOverTcpProxy").prop("checked");
        var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");

        $("#txtDnsOverTcpProxyPort").prop("disabled", !enableDnsOverTcpProxy);
        $("#txtDnsReverseProxyNetworkACL").prop("disabled", !chkEnableEDnsClientSubnetSourceAddress && !enableDnsOverUdpProxy && !enableDnsOverTcpProxy && !enableDnsOverHttp && !enableDnsOverHttps);
    });

    $("#chkEnableDnsOverHttp").on("click", function () {
        var chkEnableEDnsClientSubnetSourceAddress = $("#chkEnableEDnsClientSubnetSourceAddress").prop("checked");
        var enableDnsOverUdpProxy = $("#chkEnableDnsOverUdpProxy").prop("checked");
        var enableDnsOverTcpProxy = $("#chkEnableDnsOverTcpProxy").prop("checked");
        var enableDnsOverHttpUnixSocket = $("#chkEnableDnsOverHttpUnixSocket").prop("checked");
        var enableDnsOverHttpsUnixSocket = $("#chkEnableDnsOverHttpsUnixSocket").prop("checked");
        var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");

        $("#txtDnsOverHttpPort").prop("disabled", !enableDnsOverHttp);
        $("#txtDnsReverseProxyNetworkACL").prop("disabled", !chkEnableEDnsClientSubnetSourceAddress && !enableDnsOverUdpProxy && !enableDnsOverTcpProxy && !enableDnsOverHttp && !enableDnsOverHttps);
        $("#txtDnsOverHttpRealIpHeader").prop("disabled", !enableDnsOverHttpUnixSocket && !enableDnsOverHttpsUnixSocket && !enableDnsOverHttp && !enableDnsOverHttps);
    });

    $("#chkEnableDnsOverHttpUnixSocket").on("click", function () {
        var enableDnsOverHttpUnixSocket = $("#chkEnableDnsOverHttpUnixSocket").prop("checked");
        var enableDnsOverHttpsUnixSocket = $("#chkEnableDnsOverHttpsUnixSocket").prop("checked");
        var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");

        $("#txtDnsOverHttpUnixSocket").prop("disabled", !enableDnsOverHttpUnixSocket);
        $("#txtDnsOverHttpRealIpHeader").prop("disabled", !enableDnsOverHttpUnixSocket && !enableDnsOverHttpsUnixSocket && !enableDnsOverHttp && !enableDnsOverHttps);
    });

    $("#chkEnableDnsOverHttpsUnixSocket").on("click", function () {
        var enableDnsOverHttpUnixSocket = $("#chkEnableDnsOverHttpUnixSocket").prop("checked");
        var enableDnsOverHttpsUnixSocket = $("#chkEnableDnsOverHttpsUnixSocket").prop("checked");
        var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");
        var enableDnsOverTls = $("#chkEnableDnsOverTls").prop("checked");
        var enableDnsOverQuic = $("#chkEnableDnsOverQuic").prop("checked");

        $("#txtDnsOverHttpsUnixSocket").prop("disabled", !enableDnsOverHttpsUnixSocket);
        $("#txtDnsTlsCertificatePath").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic && !enableDnsOverHttpsUnixSocket);
        $("#txtDnsTlsCertificatePassword").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic && !enableDnsOverHttpsUnixSocket);
        $("#txtDnsOverHttpRealIpHeader").prop("disabled", !enableDnsOverHttpUnixSocket && !enableDnsOverHttpsUnixSocket && !enableDnsOverHttp && !enableDnsOverHttps);
    });

    $("#chkEnableDnsOverTls").on("click", function () {
        var enableDnsOverHttpsUnixSocket = $("#chkEnableDnsOverHttpsUnixSocket").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");
        var enableDnsOverTls = $("#chkEnableDnsOverTls").prop("checked");
        var enableDnsOverQuic = $("#chkEnableDnsOverQuic").prop("checked");

        $("#txtDnsOverTlsPort").prop("disabled", !enableDnsOverTls);
        $("#txtDnsTlsCertificatePath").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic && !enableDnsOverHttpsUnixSocket);
        $("#txtDnsTlsCertificatePassword").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic && !enableDnsOverHttpsUnixSocket);
    });

    $("#chkEnableDnsOverHttps").on("click", function () {
        var chkEnableEDnsClientSubnetSourceAddress = $("#chkEnableEDnsClientSubnetSourceAddress").prop("checked");
        var enableDnsOverUdpProxy = $("#chkEnableDnsOverUdpProxy").prop("checked");
        var enableDnsOverTcpProxy = $("#chkEnableDnsOverTcpProxy").prop("checked");
        var enableDnsOverHttpUnixSocket = $("#chkEnableDnsOverHttpUnixSocket").prop("checked");
        var enableDnsOverHttpsUnixSocket = $("#chkEnableDnsOverHttpsUnixSocket").prop("checked");
        var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");
        var enableDnsOverTls = $("#chkEnableDnsOverTls").prop("checked");
        var enableDnsOverQuic = $("#chkEnableDnsOverQuic").prop("checked");

        $("#chkEnableDnsOverHttp3").prop("disabled", !enableDnsOverHttps);
        $("#txtDnsOverHttpsPort").prop("disabled", !enableDnsOverHttps);
        $("#txtDnsReverseProxyNetworkACL").prop("disabled", !chkEnableEDnsClientSubnetSourceAddress && !enableDnsOverUdpProxy && !enableDnsOverTcpProxy && !enableDnsOverHttp && !enableDnsOverHttps);
        $("#txtDnsTlsCertificatePath").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic && !enableDnsOverHttpsUnixSocket);
        $("#txtDnsTlsCertificatePassword").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic && !enableDnsOverHttpsUnixSocket);
        $("#txtDnsOverHttpRealIpHeader").prop("disabled", !enableDnsOverHttpUnixSocket && !enableDnsOverHttpsUnixSocket && !enableDnsOverHttp && !enableDnsOverHttps);
    });

    $("#chkEnableDnsOverQuic").on("click", function () {
        var enableDnsOverHttpsUnixSocket = $("#chkEnableDnsOverHttpsUnixSocket").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");
        var enableDnsOverTls = $("#chkEnableDnsOverTls").prop("checked");
        var enableDnsOverQuic = $("#chkEnableDnsOverQuic").prop("checked");

        $("#txtDnsOverQuicPort").prop("disabled", !enableDnsOverQuic);
        $("#txtDnsTlsCertificatePath").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic && !enableDnsOverHttpsUnixSocket);
        $("#txtDnsTlsCertificatePassword").prop("disabled", !enableDnsOverTls && !enableDnsOverHttps && !enableDnsOverQuic && !enableDnsOverHttpsUnixSocket);
    });

    $("#chkEnableConcurrentForwarding").on("click", function () {
        var concurrentForwarding = $("#chkEnableConcurrentForwarding").prop("checked");
        $("#txtForwarderConcurrency").prop("disabled", !concurrentForwarding)
    });

    $("input[type=radio][name=rdLoggingType]").on("change", function () {
        var rdLoggingType = $("input[name=rdLoggingType]:checked").val();
        var enableLogging = rdLoggingType.toLowerCase() != "none";

        $("#chkIgnoreResolverLogs").prop("disabled", !enableLogging);
        $("#chkNoStackTrace").prop("disabled", !enableLogging);
        $("#chkLogQueries").prop("disabled", !enableLogging);
        $("#chkUseLocalTime").prop("disabled", !enableLogging);
        $("#txtLogFolderPath").prop("disabled", !enableLogging);
    });

    $("#chkServeStale").on("click", function () {
        var serveStale = $("#chkServeStale").prop("checked");
        $("#txtServeStaleTtl").prop("disabled", !serveStale);
        $("#txtServeStaleAnswerTtl").prop("disabled", !serveStale);
        $("#txtServeStaleResetTtl").prop("disabled", !serveStale);
        $("#txtServeStaleMaxWaitTime").prop("disabled", !serveStale);
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

            var startVal = $("#dpCustomDayWiseStart").val();
            var endVal = $("#dpCustomDayWiseEnd").val();
            if (!startVal || !endVal) {
                $("#dpCustomDayWiseStart").val(moment().subtract(24, "hours").format("YYYY-MM-DDTHH:mm"));
                $("#dpCustomDayWiseEnd").val(moment().format("YYYY-MM-DDTHH:mm"));
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

    window.setCustomRangePreset = function (preset) {
        var now = moment();
        var start;
        switch (preset) {
            case "today":
                start = moment().startOf("day");
                break;
            case "yesterday":
                start = moment().subtract(1, "days").startOf("day");
                now = moment().subtract(1, "days").endOf("day");
                break;
            case "3d":
                start = moment().subtract(3, "days");
                break;
            case "14d":
                start = moment().subtract(14, "days");
                break;
            default:
                start = moment().subtract(24, "hours");
                break;
        }
        $("#dpCustomDayWiseStart").val(start.format("YYYY-MM-DDTHH:mm"));
        $("#dpCustomDayWiseEnd").val(now.format("YYYY-MM-DDTHH:mm"));
        refreshDashboard();
    };

    // Initialize saved subview
    var savedSubView = localStorage.getItem("dashboard_chart_subview") || "traffic";
    switchDashboardChartView(savedSubView);

    // Initialize Auto-Refresh Cadence
    var savedCadence = localStorage.getItem("dashboard_auto_refresh_cadence") || "10000";
    setAutoRefreshInterval(savedCadence);

    // Visibility change listener to pause/resume auto-refresh
    document.addEventListener("visibilitychange", function () {
        if (document.hidden) {
            stopAutoRefreshTimer();
            $("#livePulseBeacon, #livePulseBeaconLegacy").addClass("paused");
        } else {
            if (autoRefreshInterval > 0 && isDashboardTabActive) {
                var beaconClass = autoRefreshInterval === 3000 ? "live-pulse-beacon fast" : "live-pulse-beacon";
                $("#livePulseBeacon, #livePulseBeaconLegacy").attr("class", beaconClass);
                startAutoRefreshTimer();
                pollLiveMetrics();
            }
        }
    });

    // Classic tab listener for shown.bs.tab to pause/resume auto-refresh
    $('a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
        var target = $(e.target).attr("href");
        if (target === "#mainPanelTabPaneDashboard") {
            isDashboardTabActive = true;
            startAutoRefreshTimer();
        } else {
            isDashboardTabActive = false;
            stopAutoRefreshTimer();
        }
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

function initUpdateNotificationMenu() {
    var disableUpdateNotification = localStorage.getItem("disableUpdateNotification");
    if (disableUpdateNotification === "true") {
        $("#mnuDisableCheckForUpdateNotification, #mnuSidebarDisableCheckForUpdateNotification, #mnuTopbarDisableCheckForUpdateNotification").hide();
        $("#mnuEnableCheckForUpdateNotification, #mnuSidebarEnableCheckForUpdateNotification, #mnuTopbarEnableCheckForUpdateNotification").show();
    }
    else {
        $("#mnuEnableCheckForUpdateNotification, #mnuSidebarEnableCheckForUpdateNotification, #mnuTopbarEnableCheckForUpdateNotification").hide();
        $("#mnuDisableCheckForUpdateNotification, #mnuSidebarDisableCheckForUpdateNotification, #mnuTopbarDisableCheckForUpdateNotification").show();
    }
}

function disableUpdateNotification() {
    if (!confirm("Disabling update notification will prevent the Web Console from showing new update notification when you login. You will have to manually find out if a new update is available.\r\n\r\nAre you sure you want to disable update notification?"))
        return;

    localStorage.setItem("disableUpdateNotification", true);
    $("#mnuDisableCheckForUpdateNotification, #mnuSidebarDisableCheckForUpdateNotification, #mnuTopbarDisableCheckForUpdateNotification").hide();
    $("#mnuEnableCheckForUpdateNotification, #mnuSidebarEnableCheckForUpdateNotification, #mnuTopbarEnableCheckForUpdateNotification").show();
    $("#lnkUpdateAvailable").hide();
    $("#lnkUpdateAvailableModern").hide();
    $("#sidebarUpdateDot").hide();

    showAlert("success", "Notification Disabled!", "Update notification was disabled successfully.");
}

function enableUpdateNotification() {
    localStorage.setItem("disableUpdateNotification", false);
    $("#mnuEnableCheckForUpdateNotification, #mnuSidebarEnableCheckForUpdateNotification, #mnuTopbarEnableCheckForUpdateNotification").hide();
    $("#mnuDisableCheckForUpdateNotification, #mnuSidebarDisableCheckForUpdateNotification, #mnuTopbarDisableCheckForUpdateNotification").show();

    showAlert("success", "Notification Enabled!", "Update notification was enabled successfully.");
}

function checkForUpdate(force) {
    if (!force) {
        var disableUpdateNotification = localStorage.getItem("disableUpdateNotification");
        if (disableUpdateNotification === "true")
            return;
    }

    HTTPRequest({
        url: "api/user/checkForUpdate",
        token: sessionData.token,
        success: function (responseJSON) {
            var lnkUpdateAvailable = $("#lnkUpdateAvailable");

            if (responseJSON.response.updateAvailable) {
                $("#lblUpdateVersion").text(responseJSON.response.updateVersion);
                $("#lblCurrentVersion").text(responseJSON.response.currentVersion);

                if (responseJSON.response.updateTitle == null)
                    responseJSON.response.updateTitle = "New Update Available!";

                lnkUpdateAvailable.text(responseJSON.response.updateTitle);
                $("#lblUpdateAvailableTitle").text(responseJSON.response.updateTitle);
                $("#lnkUpdateAvailableModern").html("<i class='fa fa-bell'></i> " + responseJSON.response.updateTitle);

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
                $("#lnkUpdateAvailableModern").show();
                $("#sidebarUpdateDot").show();
            }
            else {
                lnkUpdateAvailable.hide();
                $("#lnkUpdateAvailableModern").hide();
                $("#sidebarUpdateDot").hide();

                if (force) {
                    if (responseJSON.response.dnsServerEnableCheckForUpdate)
                        showAlert("success", "No Update Available!", "Check for update was done and no new update was found to be available.");
                    else
                        showAlert("danger", "Update Check Disabled!", "Failed to check for update due to Check For Update option being disabled on the DNS Server.");
                }
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
    localStorage.setItem("settingsClusterNode", node);

    divDnsSettings.hide();
    divDnsSettingsLoader.show();

    HTTPRequest({
        url: "api/settings/get?node=" + encodeURIComponent(node),
        token: sessionData.token,
        success: function (responseJSON) {
            if ((node == "") || (node == "cluster") || (node == sessionData.info.dnsServerDomain))
                updateDnsSettingsDataAndGui(responseJSON);

            loadDnsSettings(responseJSON);
            checkForReverseProxy(responseJSON);

            if (sessionData.info.permissions.Settings.canModify) {
                $("#btnSaveSettings").show();
            } else {
                $("#btnSaveSettings").hide();
            }

            if (sessionData.info.permissions.Cache.canDelete) {
                $("#btnSettingsFlushCache").show();
            } else {
                $("#btnSettingsFlushCache").hide();
            }

            if (sessionData.info.permissions.Settings.canDelete) {
                $("#btnShowBackupSettingsModal").show();
                $("#btnShowRestoreSettingsModal").show();
            }
            else {
                $("#btnShowBackupSettingsModal").hide();
                $("#btnShowRestoreSettingsModal").hide();
            }

            if (node == "cluster") {
                //cluster view
                //general
                $("#divSettingsGeneralLocalParameters").hide();
                $("#divSettingsGeneralDefaultParameters").show();
                $("#divSettingsGeneralSoftwareUpdate").show();
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
                $("#btnSettingsFlushCache").prop("disabled", true);
                $("#btnShowBackupSettingsModal").prop("disabled", true);
                $("#btnShowRestoreSettingsModal").prop("disabled", true);
            }
            else if (node != "") {
                //node view
                //general
                $("#divSettingsGeneralLocalParameters").show();
                $("#divSettingsGeneralDefaultParameters").hide();
                $("#divSettingsGeneralSoftwareUpdate").hide();
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
                $("#btnSettingsFlushCache").prop("disabled", false);
                $("#btnShowBackupSettingsModal").prop("disabled", false);
                $("#btnShowRestoreSettingsModal").prop("disabled", false);
            }
            else {
                //clustering disabled
                //general
                $("#divSettingsGeneralLocalParameters").show();
                $("#divSettingsGeneralDefaultParameters").show();
                $("#divSettingsGeneralSoftwareUpdate").show();
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
                $("#btnSettingsFlushCache").prop("disabled", false);
                $("#btnShowBackupSettingsModal").prop("disabled", false);
                $("#btnShowRestoreSettingsModal").prop("disabled", false);
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
    $("#txtDefaultNsRecordTtl").val(responseJSON.response.defaultNsRecordTtl);
    $("#txtDefaultSoaRecordTtl").val(responseJSON.response.defaultSoaRecordTtl);

    sessionData.info.defaultRecordTtl = responseJSON.response.defaultRecordTtl;
    sessionData.info.defaultNsRecordTtl = responseJSON.response.defaultNsRecordTtl;
    sessionData.info.defaultSoaRecordTtl = responseJSON.response.defaultSoaRecordTtl;

    $("#txtDefaultResponsiblePerson").val(responseJSON.response.defaultResponsiblePerson);
    $("#chkUseSoaSerialDateScheme").prop("checked", responseJSON.response.useSoaSerialDateScheme);
    $("#txtMinSoaRefresh").val(responseJSON.response.minSoaRefresh);
    $("#txtMinSoaRetry").val(responseJSON.response.minSoaRetry);

    $("#txtZoneTransferAllowedNetworks").val(getArrayAsString(responseJSON.response.zoneTransferAllowedNetworks));
    $("#txtNotifyAllowedNetworks").val(getArrayAsString(responseJSON.response.notifyAllowedNetworks));

    $("#chkDnsServerEnableCheckForUpdate").prop("checked", responseJSON.response.dnsServerEnableCheckForUpdate);
    $("#chkDnsAppsEnableAutomaticUpdate").prop("checked", responseJSON.response.dnsAppsEnableAutomaticUpdate);

    switch (responseJSON.response.ipv6Mode) {
        case "Enabled":
            $("#rdIPv6ModeEnabled").prop("checked", true);
            break;

        case "Preferred":
            $("#rdIPv6ModePreferred").prop("checked", true);
            break;

        case "Disabled":
        default:
            $("#rdIPv6ModeDisabled").prop("checked", true);
            break;
    }

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
    $("#txtUdpSendBufferSizeKB").val(responseJSON.response.udpSendBufferSizeKB);
    $("#txtUdpReceiveBufferSizeKB").val(responseJSON.response.udpReceiveBufferSizeKB);
    $("#txtMaxConcurrentResolutionsPerCore").val(responseJSON.response.maxConcurrentResolutionsPerCore);

    //web service
    var webServiceLocalAddresses = responseJSON.response.webServiceLocalAddresses;
    if (webServiceLocalAddresses == null)
        $("#txtWebServiceLocalAddresses").val("");
    else
        $("#txtWebServiceLocalAddresses").val(getArrayAsString(webServiceLocalAddresses));

    $("#txtWebServiceHttpPort").val(responseJSON.response.webServiceHttpPort);

    $("#chkWebServiceEnableHttpUnixSocket").prop("checked", responseJSON.response.webServiceEnableHttpUnixSocket);
    $("#txtWebServiceHttpUnixSocket").prop("disabled", !responseJSON.response.webServiceEnableHttpUnixSocket);
    $("#txtWebServiceHttpUnixSocket").val(responseJSON.response.webServiceHttpUnixSocket);

    $("#chkWebServiceEnableTlsUnixSocket").prop("checked", responseJSON.response.webServiceEnableTlsUnixSocket);
    $("#txtWebServiceTlsUnixSocket").prop("disabled", !responseJSON.response.webServiceEnableTlsUnixSocket);
    $("#txtWebServiceTlsUnixSocket").val(responseJSON.response.webServiceTlsUnixSocket);

    $("#chkWebServiceEnableTls").prop("checked", responseJSON.response.webServiceEnableTls);

    $("#chkWebServiceEnableHttp3").prop("disabled", !responseJSON.response.webServiceEnableTls);
    $("#chkWebServiceHttpToTlsRedirect").prop("disabled", !responseJSON.response.webServiceEnableTls);
    $("#chkWebServiceUseSelfSignedTlsCertificate").prop("disabled", !responseJSON.response.webServiceEnableTls && !responseJSON.response.webServiceEnableTlsUnixSocket);
    $("#txtWebServiceTlsPort").prop("disabled", !responseJSON.response.webServiceEnableTls);

    $("#chkWebServiceEnableHttp3").prop("checked", responseJSON.response.webServiceEnableHttp3);
    $("#chkWebServiceHttpToTlsRedirect").prop("checked", responseJSON.response.webServiceHttpToTlsRedirect);
    $("#chkWebServiceUseSelfSignedTlsCertificate").prop("checked", responseJSON.response.webServiceUseSelfSignedTlsCertificate);
    $("#txtWebServiceTlsPort").val(responseJSON.response.webServiceTlsPort);

    $("#txtWebServiceReverseProxyAddresses").val(getArrayAsString(responseJSON.response.webServiceReverseProxyAddresses));

    $("#txtWebServiceRealIpHeader").val(responseJSON.response.webServiceRealIpHeader);
    $("#lblWebServiceRealIpHeader").text(responseJSON.response.webServiceRealIpHeader);
    $("#lblWebServiceRealIpNginx").text("proxy_set_header " + responseJSON.response.webServiceRealIpHeader + " $remote_addr;");

    $("#txtWebServiceCspFrameAncestorsHeader").val(responseJSON.response.webServiceCspFrameAncestorsHeader);

    $("#txtWebServiceTlsCertificatePath").prop("disabled", !responseJSON.response.webServiceEnableTls && !responseJSON.response.webServiceEnableTlsUnixSocket);
    $("#txtWebServiceTlsCertificatePassword").prop("disabled", !responseJSON.response.webServiceEnableTls && !responseJSON.response.webServiceEnableTlsUnixSocket);

    $("#txtWebServiceTlsCertificatePath").val(responseJSON.response.webServiceTlsCertificatePath);

    if (responseJSON.response.webServiceTlsCertificatePath == null)
        $("#txtWebServiceTlsCertificatePassword").val("");
    else
        $("#txtWebServiceTlsCertificatePassword").val(responseJSON.response.webServiceTlsCertificatePassword);

    //optional protocols
    $("#chkEnableEDnsClientSubnetSourceAddress").prop("checked", responseJSON.response.enableEDnsClientSubnetSourceAddress);
    $("#chkEnableDnsOverUdpProxy").prop("checked", responseJSON.response.enableDnsOverUdpProxy);
    $("#chkEnableDnsOverTcpProxy").prop("checked", responseJSON.response.enableDnsOverTcpProxy);
    $("#chkEnableDnsOverHttp").prop("checked", responseJSON.response.enableDnsOverHttp);
    $("#chkEnableDnsOverHttpUnixSocket").prop("checked", responseJSON.response.enableDnsOverHttpUnixSocket);
    $("#chkEnableDnsOverHttpsUnixSocket").prop("checked", responseJSON.response.enableDnsOverHttpsUnixSocket);
    $("#chkEnableDnsOverTls").prop("checked", responseJSON.response.enableDnsOverTls);
    $("#chkEnableDnsOverHttps").prop("checked", responseJSON.response.enableDnsOverHttps);
    $("#chkEnableDnsOverHttp3").prop("disabled", !responseJSON.response.enableDnsOverHttps);
    $("#chkEnableDnsOverHttp3").prop("checked", responseJSON.response.enableDnsOverHttp3);
    $("#chkEnableDnsOverQuic").prop("checked", responseJSON.response.enableDnsOverQuic);

    $("#chkEnableDnsOverHttpHelpRedirect").prop("checked", responseJSON.response.enableDnsOverHttpHelpRedirect);

    $("#txtDnsOverUdpProxyPort").prop("disabled", !responseJSON.response.enableDnsOverUdpProxy);
    $("#txtDnsOverTcpProxyPort").prop("disabled", !responseJSON.response.enableDnsOverTcpProxy);
    $("#txtDnsOverHttpPort").prop("disabled", !responseJSON.response.enableDnsOverHttp);
    $("#txtDnsOverHttpUnixSocket").prop("disabled", !responseJSON.response.enableDnsOverHttpUnixSocket);
    $("#txtDnsOverHttpsUnixSocket").prop("disabled", !responseJSON.response.enableDnsOverHttpsUnixSocket);
    $("#txtDnsOverTlsPort").prop("disabled", !responseJSON.response.enableDnsOverTls);
    $("#txtDnsOverHttpsPort").prop("disabled", !responseJSON.response.enableDnsOverHttps);
    $("#txtDnsOverQuicPort").prop("disabled", !responseJSON.response.enableDnsOverQuic);

    $("#txtDnsOverUdpProxyPort").val(responseJSON.response.dnsOverUdpProxyPort);
    $("#txtDnsOverTcpProxyPort").val(responseJSON.response.dnsOverTcpProxyPort);
    $("#txtDnsOverHttpPort").val(responseJSON.response.dnsOverHttpPort);
    $("#txtDnsOverHttpUnixSocket").val(responseJSON.response.dnsOverHttpUnixSocket);
    $("#txtDnsOverHttpsUnixSocket").val(responseJSON.response.dnsOverHttpsUnixSocket);
    $("#txtDnsOverTlsPort").val(responseJSON.response.dnsOverTlsPort);
    $("#txtDnsOverHttpsPort").val(responseJSON.response.dnsOverHttpsPort);
    $("#txtDnsOverQuicPort").val(responseJSON.response.dnsOverQuicPort);

    $("#txtDnsReverseProxyNetworkACL").prop("disabled", !responseJSON.response.enableEDnsClientSubnetSourceAddress && !responseJSON.response.enableDnsOverUdpProxy && !responseJSON.response.enableDnsOverTcpProxy && !responseJSON.response.enableDnsOverHttp && !responseJSON.response.enableDnsOverHttps);
    $("#txtDnsReverseProxyNetworkACL").val(getArrayAsString(responseJSON.response.dnsReverseProxyNetworkACL));

    $("#txtDnsOverHttpRealIpHeader").prop("disabled", !responseJSON.response.enableDnsOverHttpUnixSocket && !responseJSON.response.enableDnsOverHttpsUnixSocket && !responseJSON.response.enableDnsOverHttp && !responseJSON.response.enableDnsOverHttps);
    $("#txtDnsOverHttpRealIpHeader").val(responseJSON.response.dnsOverHttpRealIpHeader);
    $("#lblDnsOverHttpRealIpHeader").text(responseJSON.response.dnsOverHttpRealIpHeader);
    $("#lblDnsOverHttpRealIpNginx").text("proxy_set_header " + responseJSON.response.dnsOverHttpRealIpHeader + " $remote_addr;");

    $("#txtDnsTlsCertificatePath").prop("disabled", !responseJSON.response.enableDnsOverTls && !responseJSON.response.enableDnsOverHttps && !responseJSON.response.enableDnsOverQuic && !responseJSON.response.enableDnsOverHttpsUnixSocket);
    $("#txtDnsTlsCertificatePassword").prop("disabled", !responseJSON.response.enableDnsOverTls && !responseJSON.response.enableDnsOverHttps && !responseJSON.response.enableDnsOverQuic && !responseJSON.response.enableDnsOverHttpsUnixSocket);

    $("#txtDnsTlsCertificatePath").val(responseJSON.response.dnsTlsCertificatePath);

    if (responseJSON.response.dnsTlsCertificatePath == null)
        $("#txtDnsTlsCertificatePassword").val("");
    else
        $("#txtDnsTlsCertificatePassword").val(responseJSON.response.dnsTlsCertificatePassword);

    $("#lblDoHHost").text(window.location.hostname + (responseJSON.response.dnsOverHttpPort == 80 ? "" : ":" + responseJSON.response.dnsOverHttpPort));
    $("#lblDoTHost").text("tls-certificate-domain:" + responseJSON.response.dnsOverTlsPort);
    $("#lblDoQHost").text("tls-certificate-domain:" + responseJSON.response.dnsOverQuicPort);
    $("#lblDoHsHost").text("tls-certificate-domain" + (responseJSON.response.dnsOverHttpsPort == 443 ? "" : ":" + responseJSON.response.dnsOverHttpsPort));

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
    $("#chkLocallyServedDnsZones").prop("checked", responseJSON.response.locallyServedDnsZones);

    $("#txtResolverRetries").val(responseJSON.response.resolverRetries);
    $("#txtResolverTimeout").val(responseJSON.response.resolverTimeout);
    $("#txtResolverConcurrency").val(responseJSON.response.resolverConcurrency);
    $("#txtResolverMaxStackCount").val(responseJSON.response.resolverMaxStackCount);

    //cache
    $("#chkSaveCache").prop("checked", responseJSON.response.saveCache);

    $("#chkServeStale").prop("checked", responseJSON.response.serveStale);

    $("#txtServeStaleTtl").prop("disabled", !responseJSON.response.serveStale);
    $("#txtServeStaleAnswerTtl").prop("disabled", !responseJSON.response.serveStale);
    $("#txtServeStaleResetTtl").prop("disabled", !responseJSON.response.serveStale);
    $("#txtServeStaleMaxWaitTime").prop("disabled", !responseJSON.response.serveStale);

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

    //blocking
    $("#chkEnableBlocking").prop("checked", responseJSON.response.enableBlocking);

    $("#chkAllowTxtBlockingReport").prop("disabled", !responseJSON.response.enableBlocking);
    $("#txtTemporaryDisableBlockingMinutes").prop("disabled", !responseJSON.response.enableBlocking);
    $("#btnTemporaryDisableBlockingNow").prop("disabled", !responseJSON.response.enableBlocking);
    $("#txtBlockingBypassList").prop("disabled", !responseJSON.response.enableBlocking);
    $("#rdBlockingTypeAnyAddress").prop("disabled", !responseJSON.response.enableBlocking);
    $("#rdBlockingTypeNxDomain").prop("disabled", !responseJSON.response.enableBlocking);
    $("#rdBlockingTypeCustomAddress").prop("disabled", !responseJSON.response.enableBlocking);
    $("#txtBlockingAnswerTtl").prop("disabled", !responseJSON.response.enableBlocking);
    $("#txtBlockListUrls").prop("disabled", !responseJSON.response.enableBlocking);
    $("#optQuickBlockList").prop("disabled", !responseJSON.response.enableBlocking);

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
        $("#btnUpdateBlockListsNow").prop("disabled", false);
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
    $("#chkNoStackTrace").prop("disabled", !enableLogging);
    $("#chkLogQueries").prop("disabled", !enableLogging);
    $("#chkUseLocalTime").prop("disabled", !enableLogging);
    $("#txtLogFolderPath").prop("disabled", !enableLogging);

    $("#chkIgnoreResolverLogs").prop("checked", responseJSON.response.ignoreResolverLogs);
    $("#chkNoStackTrace").prop("checked", responseJSON.response.noStackTrace);
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
        var defaultNsRecordTtl = $("#txtDefaultNsRecordTtl").val();
        var defaultSoaRecordTtl = $("#txtDefaultSoaRecordTtl").val();
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

        var dnsServerEnableCheckForUpdate = $("#chkDnsServerEnableCheckForUpdate").prop("checked");
        var dnsAppsEnableAutomaticUpdate = $("#chkDnsAppsEnableAutomaticUpdate").prop("checked");

        formData += "&defaultRecordTtl=" + encodeURIComponent(defaultRecordTtl) + "&defaultNsRecordTtl=" + encodeURIComponent(defaultNsRecordTtl) + "&defaultSoaRecordTtl=" + encodeURIComponent(defaultSoaRecordTtl) + "&defaultResponsiblePerson=" + encodeURIComponent(defaultResponsiblePerson) + "&useSoaSerialDateScheme=" + useSoaSerialDateScheme + "&minSoaRefresh=" + encodeURIComponent(minSoaRefresh) + "&minSoaRetry=" + encodeURIComponent(minSoaRetry) + "&zoneTransferAllowedNetworks=" + encodeURIComponent(zoneTransferAllowedNetworks) + "&notifyAllowedNetworks=" + encodeURIComponent(notifyAllowedNetworks) + "&dnsServerEnableCheckForUpdate=" + dnsServerEnableCheckForUpdate + "&dnsAppsEnableAutomaticUpdate=" + dnsAppsEnableAutomaticUpdate;
    }

    if (includeNodeParameters) {
        var ipv6Mode = $("input[name=rdIPv6Mode]:checked").val();
        var enableUdpSocketPool = $("#chkEnableUdpSocketPool").prop("checked");

        var socketPoolExcludedPorts = cleanTextList($("#txtUdpSocketPoolExcludedPorts").val());
        if ((socketPoolExcludedPorts.length == 0) || (socketPoolExcludedPorts === ","))
            socketPoolExcludedPorts = false;
        else
            $("#txtUdpSocketPoolExcludedPorts").val(socketPoolExcludedPorts.replace(/,/g, "\n") + "\n");

        formData += "&ipv6Mode=" + ipv6Mode + "&enableUdpSocketPool=" + enableUdpSocketPool + "&socketPoolExcludedPorts=" + encodeURIComponent(socketPoolExcludedPorts);
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

        var udpSendBufferSizeKB = $("#txtUdpSendBufferSizeKB").val();
        if ((udpSendBufferSizeKB == null) || (udpSendBufferSizeKB === "")) {
            showAlert("warning", "Missing!", "Please enter a value for UDP Send Buffer Size.");
            $("#txtUdpSendBufferSizeKB").trigger("focus");
            return;
        }

        var udpReceiveBufferSizeKB = $("#txtUdpReceiveBufferSizeKB").val();
        if ((udpReceiveBufferSizeKB == null) || (udpReceiveBufferSizeKB === "")) {
            showAlert("warning", "Missing!", "Please enter a value for UDP Receive Buffer Size.");
            $("#txtUdpReceiveBufferSizeKB").trigger("focus");
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
        formData += "&clientTimeout=" + clientTimeout + "&tcpSendTimeout=" + tcpSendTimeout + "&tcpReceiveTimeout=" + tcpReceiveTimeout + "&quicIdleTimeout=" + quicIdleTimeout + "&quicMaxInboundStreams=" + quicMaxInboundStreams + "&listenBacklog=" + listenBacklog + "&udpSendBufferSizeKB=" + udpSendBufferSizeKB + "&udpReceiveBufferSizeKB=" + udpReceiveBufferSizeKB + "&maxConcurrentResolutionsPerCore=" + maxConcurrentResolutionsPerCore;
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

        var webServiceEnableHttpUnixSocket = $("#chkWebServiceEnableHttpUnixSocket").prop("checked");
        var webServiceHttpUnixSocket = $("#txtWebServiceHttpUnixSocket").val();

        var webServiceEnableTlsUnixSocket = $("#chkWebServiceEnableTlsUnixSocket").prop("checked");
        var webServiceTlsUnixSocket = $("#txtWebServiceTlsUnixSocket").val();

        var webServiceEnableTls = $("#chkWebServiceEnableTls").prop("checked");
        var webServiceEnableHttp3 = $("#chkWebServiceEnableHttp3").prop("checked");
        var webServiceHttpToTlsRedirect = $("#chkWebServiceHttpToTlsRedirect").prop("checked");
        var webServiceUseSelfSignedTlsCertificate = $("#chkWebServiceUseSelfSignedTlsCertificate").prop("checked");
        var webServiceTlsPort = $("#txtWebServiceTlsPort").val();

        var webServiceReverseProxyAddresses = cleanTextList($("#txtWebServiceReverseProxyAddresses").val());

        if ((webServiceReverseProxyAddresses.length === 0) || (webServiceReverseProxyAddresses === ","))
            webServiceReverseProxyAddresses = false;
        else
            $("#txtWebServiceReverseProxyAddresses").val(webServiceReverseProxyAddresses.replace(/,/g, "\n"));

        var webServiceRealIpHeader = $("#txtWebServiceRealIpHeader").val();
        var webServiceCspFrameAncestorsHeader = $("#txtWebServiceCspFrameAncestorsHeader").val();

        var webServiceTlsCertificatePath = $("#txtWebServiceTlsCertificatePath").val();
        var webServiceTlsCertificatePassword = $("#txtWebServiceTlsCertificatePassword").val();

        formData += "&webServiceLocalAddresses=" + encodeURIComponent(webServiceLocalAddresses) + "&webServiceHttpPort=" + webServiceHttpPort + "&webServiceEnableHttpUnixSocket=" + webServiceEnableHttpUnixSocket + "&webServiceHttpUnixSocket=" + encodeURIComponent(webServiceHttpUnixSocket) + "&webServiceEnableTlsUnixSocket=" + webServiceEnableTlsUnixSocket + "&webServiceTlsUnixSocket=" + encodeURIComponent(webServiceTlsUnixSocket) + "&webServiceEnableTls=" + webServiceEnableTls + "&webServiceEnableHttp3=" + webServiceEnableHttp3 + "&webServiceHttpToTlsRedirect=" + webServiceHttpToTlsRedirect + "&webServiceUseSelfSignedTlsCertificate=" + webServiceUseSelfSignedTlsCertificate + "&webServiceTlsPort=" + webServiceTlsPort + "&webServiceReverseProxyAddresses=" + encodeURIComponent(webServiceReverseProxyAddresses) + "&webServiceRealIpHeader=" + encodeURIComponent(webServiceRealIpHeader) + "&webServiceCspFrameAncestorsHeader=" + encodeURIComponent(webServiceCspFrameAncestorsHeader) + "&webServiceTlsCertificatePath=" + encodeURIComponent(webServiceTlsCertificatePath) + "&webServiceTlsCertificatePassword=" + encodeURIComponent(webServiceTlsCertificatePassword);
    }

    //optional protocols
    if (includeNodeParameters) {
        var enableEDnsClientSubnetSourceAddress = $("#chkEnableEDnsClientSubnetSourceAddress").prop("checked");
        var enableDnsOverUdpProxy = $("#chkEnableDnsOverUdpProxy").prop("checked");
        var enableDnsOverTcpProxy = $("#chkEnableDnsOverTcpProxy").prop("checked");
        var enableDnsOverHttp = $("#chkEnableDnsOverHttp").prop("checked");
        var enableDnsOverHttpUnixSocket = $("#chkEnableDnsOverHttpUnixSocket").prop("checked");
        var enableDnsOverHttpsUnixSocket = $("#chkEnableDnsOverHttpsUnixSocket").prop("checked");
        var enableDnsOverTls = $("#chkEnableDnsOverTls").prop("checked");
        var enableDnsOverHttps = $("#chkEnableDnsOverHttps").prop("checked");
        var enableDnsOverHttp3 = $("#chkEnableDnsOverHttp3").prop("checked");
        var enableDnsOverQuic = $("#chkEnableDnsOverQuic").prop("checked");

        var enableDnsOverHttpHelpRedirect = $("#chkEnableDnsOverHttpHelpRedirect").prop("checked");

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

        var dnsOverHttpUnixSocket = $("#txtDnsOverHttpUnixSocket").val();
        var dnsOverHttpsUnixSocket = $("#txtDnsOverHttpsUnixSocket").val();

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

        var dnsReverseProxyNetworkACL = cleanTextList($("#txtDnsReverseProxyNetworkACL").val());

        if ((dnsReverseProxyNetworkACL.length === 0) || (dnsReverseProxyNetworkACL === ","))
            dnsReverseProxyNetworkACL = false;
        else
            $("#txtDnsReverseProxyNetworkACL").val(dnsReverseProxyNetworkACL.replace(/,/g, "\n"));

        var dnsOverHttpRealIpHeader = $("#txtDnsOverHttpRealIpHeader").val();

        var dnsTlsCertificatePath = $("#txtDnsTlsCertificatePath").val();
        var dnsTlsCertificatePassword = $("#txtDnsTlsCertificatePassword").val();

        formData += "&enableEDnsClientSubnetSourceAddress=" + enableEDnsClientSubnetSourceAddress + "&enableDnsOverUdpProxy=" + enableDnsOverUdpProxy + "&enableDnsOverTcpProxy=" + enableDnsOverTcpProxy + "&enableDnsOverHttp=" + enableDnsOverHttp + "&enableDnsOverHttpUnixSocket=" + enableDnsOverHttpUnixSocket + "&enableDnsOverHttpsUnixSocket=" + enableDnsOverHttpsUnixSocket + "&enableDnsOverTls=" + enableDnsOverTls + "&enableDnsOverHttps=" + enableDnsOverHttps + "&enableDnsOverHttp3=" + enableDnsOverHttp3 + "&enableDnsOverQuic=" + enableDnsOverQuic + "&enableDnsOverHttpHelpRedirect=" + enableDnsOverHttpHelpRedirect + "&dnsOverUdpProxyPort=" + dnsOverUdpProxyPort + "&dnsOverTcpProxyPort=" + dnsOverTcpProxyPort + "&dnsOverHttpPort=" + dnsOverHttpPort + "&dnsOverHttpUnixSocket=" + encodeURIComponent(dnsOverHttpUnixSocket) + "&dnsOverHttpsUnixSocket=" + encodeURIComponent(dnsOverHttpsUnixSocket) + "&dnsOverTlsPort=" + dnsOverTlsPort + "&dnsOverHttpsPort=" + dnsOverHttpsPort + "&dnsOverQuicPort=" + dnsOverQuicPort + "&dnsReverseProxyNetworkACL=" + encodeURIComponent(dnsReverseProxyNetworkACL) + "&dnsOverHttpRealIpHeader=" + encodeURIComponent(dnsOverHttpRealIpHeader) + "&dnsTlsCertificatePath=" + encodeURIComponent(dnsTlsCertificatePath) + "&dnsTlsCertificatePassword=" + encodeURIComponent(dnsTlsCertificatePassword);
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
        var locallyServedDnsZones = $("#chkLocallyServedDnsZones").prop("checked");

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

        formData += "&recursion=" + recursion + "&recursionNetworkACL=" + encodeURIComponent(recursionNetworkACL) + "&randomizeName=" + randomizeName + "&qnameMinimization=" + qnameMinimization + "&locallyServedDnsZones=" + locallyServedDnsZones + "&resolverRetries=" + resolverRetries + "&resolverTimeout=" + resolverTimeout + "&resolverConcurrency=" + resolverConcurrency + "&resolverMaxStackCount=" + resolverMaxStackCount;
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

        formData += "&saveCache=" + saveCache + "&serveStale=" + serveStale + "&serveStaleTtl=" + serveStaleTtl + "&serveStaleAnswerTtl=" + serveStaleAnswerTtl + "&serveStaleResetTtl=" + serveStaleResetTtl + "&serveStaleMaxWaitTime=" + serveStaleMaxWaitTime + "&cacheMaximumEntries=" + cacheMaximumEntries + "&cacheMinimumRecordTtl=" + cacheMinimumRecordTtl + "&cacheMaximumRecordTtl=" + cacheMaximumRecordTtl + "&cacheNegativeRecordTtl=" + cacheNegativeRecordTtl + "&cacheFailureRecordTtl=" + cacheFailureRecordTtl + "&cachePrefetchEligibility=" + cachePrefetchEligibility + "&cachePrefetchTrigger=" + cachePrefetchTrigger;
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
        var noStackTrace = $("#chkNoStackTrace").prop("checked");
        var logQueries = $("#chkLogQueries").prop("checked");
        var useLocalTime = $("#chkUseLocalTime").prop("checked");
        var logFolder = $("#txtLogFolderPath").val();
        var maxLogFileDays = $("#txtMaxLogFileDays").val();

        var enableInMemoryStats = $("#chkEnableInMemoryStats").prop("checked");
        var maxStatFileDays = $("#txtMaxStatFileDays").val();

        formData += "&loggingType=" + loggingType + "&ignoreResolverLogs=" + ignoreResolverLogs + "&noStackTrace=" + noStackTrace + "&logQueries=" + logQueries + "&useLocalTime=" + useLocalTime + "&logFolder=" + encodeURIComponent(logFolder) + "&maxLogFileDays=" + maxLogFileDays + "&enableInMemoryStats=" + enableInMemoryStats + "&maxStatFileDays=" + maxStatFileDays;
    }

    //send request
    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/settings/set",
        token: sessionData.token,
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
        url: "api/settings/forceUpdateBlockLists",
        token: sessionData.token,
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
        url: "api/settings/temporaryDisableBlocking?minutes=" + minutes,
        token: sessionData.token,
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
    $("#txtBlockingAnswerTtl").prop("disabled", !enableBlocking);
    $("#txtCustomBlockingAddresses").prop("disabled", !enableBlocking || !$("#rdBlockingTypeCustomAddress").prop("checked"));
    $("#txtBlockListUrls").prop("disabled", !enableBlocking);
    $("#optQuickBlockList").prop("disabled", !enableBlocking);
}

function dashboardBlockingOptionsOnClick() {
    $("#mnuDashboardBlockingOptionsEnableBlocking").hide();
    $("#mnuDashboardBlockingOptionsDisableBlocking").hide();

    HTTPRequest({
        url: "api/settings/get",
        token: sessionData.token,
        success: function (responseJSON) {
            if (responseJSON.response.enableBlocking)
                $("#mnuDashboardBlockingOptionsDisableBlocking").show();
            else
                $("#mnuDashboardBlockingOptionsEnableBlocking").show();
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function enableBlocking() {
    if (!confirm("Are you sure you want to enable blocking?"))
        return;

    HTTPRequest({
        url: "api/settings/set?enableBlocking=true",
        token: sessionData.token,
        success: function (responseJSON) {
            showAlert("success", "Blocking Enabled!", "Blocking was enabled successfully.");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function disableBlocking() {
    if (!confirm("Are you sure you want to disable blocking?"))
        return;

    HTTPRequest({
        url: "api/settings/set?enableBlocking=false",
        token: sessionData.token,
        success: function (responseJSON) {
            showAlert("success", "Blocking Disabled!", "Blocking was disabled successfully.");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function temporaryDisableBlockingForMenu(minutes) {
    if (!confirm("Are you sure to temporarily disable blocking for " + minutes + " minute(s)?"))
        return;

    HTTPRequest({
        url: "api/settings/temporaryDisableBlocking?minutes=" + minutes,
        token: sessionData.token,
        success: function (responseJSON) {
            showAlert("success", "Blocking Disabled!", "Blocking was successfully disabled temporarily for " + htmlEncode(minutes) + " minute(s).");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

window.activeDashboardFilter = null;

var CROSS_FILTER_CORRELATIONS = {
    "Cached": {
        matches: ["Cached", "No Error", "Cached Records"]
    },
    "Recursive": {
        matches: ["Recursive", "No Error", "NX Domain"]
    },
    "Authoritative": {
        matches: ["Authoritative", "No Error", "Authoritative Zones"]
    },
    "Dropped": {
        matches: ["Dropped", "Server Failure", "Refused", "Blocked Zones"]
    },
    "Blocked": {
        matches: ["Blocked", "Dropped", "NX Domain", "Refused", "Blocked Zones"]
    },
    "No Error": {
        matches: ["No Error", "Cached", "Recursive", "Authoritative", "Cached Records"]
    },
    "NX Domain": {
        matches: ["NX Domain", "Recursive", "Dropped", "Blocked Zones"]
    },
    "Server Failure": {
        matches: ["Server Failure", "Dropped"]
    },
    "Refused": {
        matches: ["Refused", "Dropped", "Blocked Zones"]
    },
    "Cached Records": {
        matches: ["Cached Records", "Cached", "No Error"]
    },
    "Blocked Zones": {
        matches: ["Blocked Zones", "Blocked", "Dropped", "NX Domain", "Refused"]
    },
    "Allowed Zones": {
        matches: ["Allowed Zones", "Cached", "Recursive", "No Error"]
    },
    "Authoritative Zones": {
        matches: ["Authoritative Zones", "Authoritative", "No Error"]
    }
};

// --- Modern Line Legend Toggling & Interactive Control ---
function toggleMainChartDataset(datasetLabel) {
    if (!window.chartDashboardMain || !window.chartDashboardMain.data.datasets) return;
    var normTarget = (datasetLabel || '').toLowerCase().replace(/[^a-z0-9]/g, "");
    var labelFilters = [];

    window.chartDashboardMain.data.datasets.forEach(function (ds, idx) {
        var dsNorm = (ds.label || '').toLowerCase().replace(/[^a-z0-9]/g, "");
        if (dsNorm === normTarget || (normTarget === "totalqueries" && (dsNorm === "total" || dsNorm === "totalqueries"))) {
            var meta = window.chartDashboardMain.getDatasetMeta(idx);
            var isHidden = meta && meta.hidden != null ? meta.hidden : (ds.hidden || false);
            if (meta) meta.hidden = !isHidden;
            ds.hidden = !isHidden;
        }
        var currentMeta = window.chartDashboardMain.getDatasetMeta(idx);
        labelFilters.push({
            title: ds.label,
            hidden: currentMeta && currentMeta.hidden != null ? currentMeta.hidden : (ds.hidden || false)
        });
    });

    localStorage.setItem("chart_" + window.chartDashboardMain.id + "_legend", JSON.stringify(labelFilters));
    window.chartDashboardMain.update(0);
    renderMainChartLegend();
}

function renderMainChartLegend() {
    if (!window.chartDashboardMain || !window.chartDashboardMain.data.datasets) return;
    if (window.activeDashboardFilter) return; // Active filter manages legend indicator

    var allMetrics = [
        { label: "Total Queries", color: "#38bdf8" },
        { label: "Cached", color: "#10b981" },
        { label: "Recursive", color: "#6366f1" },
        { label: "Blocked", color: "#f59e0b" },
        { label: "Authoritative", color: "#8b5cf6" },
        { label: "No Error", color: "#22c55e" },
        { label: "NX Domain", color: "#ec4899" },
        { label: "Server Failure", color: "#ef4444" },
        { label: "Refused", color: "#a855f7" },
        { label: "Dropped", color: "#64748b" },
        { label: "Clients", color: "#06b6d4" }
    ];

    var html = "";
    allMetrics.forEach(function (m) {
        var normM = m.label.toLowerCase().replace(/[^a-z0-9]/g, "");
        var isVisible = true;
        for (var i = 0; i < window.chartDashboardMain.data.datasets.length; i++) {
            var ds = window.chartDashboardMain.data.datasets[i];
            var dsNorm = (ds.label || '').toLowerCase().replace(/[^a-z0-9]/g, "");
            if (dsNorm === normM || (normM === "totalqueries" && (dsNorm === "total" || dsNorm === "totalqueries"))) {
                var meta = window.chartDashboardMain.getDatasetMeta(i);
                if (meta && meta.hidden !== null && meta.hidden !== undefined) {
                    isVisible = !meta.hidden;
                } else {
                    isVisible = !ds.hidden;
                }
                break;
            }
        }
        var pillClass = isVisible ? "legend-pill active" : "legend-pill dimmed";
        html += '<span class="' + pillClass + '" onclick="toggleMainChartDataset(\'' + m.label + '\');" title="Click to toggle ' + m.label + ' line">' +
                '<span class="legend-dot" style="background:' + m.color + ';"></span> ' + m.label + '</span>';
    });
    $("#lblDashboardChartLegend").html(html);
}

function toggleDashboardFilter(category, name) {
    if (window.activeDashboardFilter && window.activeDashboardFilter.name === name) {
        clearActiveDashboardFilter();
        return;
    }
    window.activeDashboardFilter = { category: category, name: name };
    applyActiveDashboardFilter();
}

function clearActiveDashboardFilter() {
    window.activeDashboardFilter = null;
    applyActiveDashboardFilter();
}

function applyActiveDashboardFilter() {
    var filterBadge = $("#divActiveChartFilter");
    if (!window.activeDashboardFilter) {
        filterBadge.hide().empty();
        $(".clickable-filter-row").removeClass("active-filtered-row filter-correlated filter-dimmed");
        $("#lblFilterRecordType").text("Record: All");
        $("#btnFilterRecordType").removeClass("active-filter");
        $("#lblFilterProtocol").text("Protocol: All");
        $("#btnFilterProtocol").removeClass("active-filter");

        if (window.chartDashboardMain && window.lastMainChartOriginalDatasets) {
            window.chartDashboardMain.data.datasets = JSON.parse(JSON.stringify(window.lastMainChartOriginalDatasets));
            window.chartDashboardMain.update(0);
        }
        renderMainChartLegend();
        if (window.lastDashboardResponse) {
            updateChartFilterMenus(window.lastDashboardResponse);
        }
        return;
    }

    var name = window.activeDashboardFilter.name;
    var cat = window.activeDashboardFilter.category;
    var corr = CROSS_FILTER_CORRELATIONS[name] ? CROSS_FILTER_CORRELATIONS[name].matches : [name];

    // Update filter dropdown button states
    if (cat === "Record Type") {
        $("#lblFilterRecordType").text("Record: " + name);
        $("#btnFilterRecordType").addClass("active-filter");
        $("#lblFilterProtocol").text("Protocol: All");
        $("#btnFilterProtocol").removeClass("active-filter");
    } else if (cat === "Protocol") {
        $("#lblFilterProtocol").text("Protocol: " + name);
        $("#btnFilterProtocol").addClass("active-filter");
        $("#lblFilterRecordType").text("Record: All");
        $("#btnFilterRecordType").removeClass("active-filter");
    } else {
        $("#lblFilterRecordType").text("Record: All");
        $("#btnFilterRecordType").removeClass("active-filter");
        $("#lblFilterProtocol").text("Protocol: All");
        $("#btnFilterProtocol").removeClass("active-filter");
    }

    // Format rich filter chip with volume & percentage if available
    var countInfo = "";
    var targetRow = $('.clickable-filter-row[data-filter-name="' + name + '"]');
    if (targetRow.length) {
        var valText = targetRow.find(".matrix-metric-val, .breakdown-count").first().text().trim();
        var pctText = targetRow.find(".breakdown-pct-tag").first().text().trim();
        if (valText) {
            countInfo = " &bull; " + valText + (pctText ? " (" + pctText + ")" : "");
        }
    }

    filterBadge.html(
        '<span class="filter-chip-text"><i class="fa fa-filter"></i> Active Filter: <b>' + htmlEncode(name) + '</b>' + countInfo + '</span>' +
        '<button type="button" class="btn-clear-filter" onclick="clearActiveDashboardFilter(); return false;" title="Clear filter">&times;</button>'
    ).show();

    // Multi-card cross-highlighting & dimming across ALL cards
    $(".clickable-filter-row").each(function () {
        var rowName = $(this).attr("data-filter-name");
        if (!rowName) return;
        if (rowName.toLowerCase() === name.toLowerCase()) {
            $(this).addClass("active-filtered-row").removeClass("filter-correlated filter-dimmed");
        } else if (corr.some(function (c) { return c.toLowerCase() === rowName.toLowerCase(); })) {
            $(this).addClass("filter-correlated").removeClass("active-filtered-row filter-dimmed");
        } else {
            $(this).addClass("filter-dimmed").removeClass("active-filtered-row filter-correlated");
        }
    });

    // Spotlight the filtered metric on the main chart with Total reference boundary
    if (window.chartDashboardMain && window.lastMainChartOriginalDatasets) {
        var filteredDatasets = [];
        var totDs = window.lastMainChartOriginalDatasets.find(function(d) {
            var l = (d.label || '').toLowerCase().replace(/[^a-z0-9]/g, "");
            return l === 'total' || l === 'totalqueries';
        });

        var isRecordOrProtocol = (cat === "Record Type" || cat === "Protocol");
        var filterVolume = 0;
        var totalQueriesCount = (window.lastDashboardResponse && window.lastDashboardResponse.stats) ? window.lastDashboardResponse.stats.totalQueries : 0;
        if (totalQueriesCount <= 0 && totDs && totDs.data) {
            totalQueriesCount = totDs.data.reduce(function(a, b) { return a + b; }, 0);
        }

        if (window.lastDashboardResponse) {
            if (window.lastDashboardResponse.queryTypeChartData && window.lastDashboardResponse.queryTypeChartData.labels) {
                var qIdx = window.lastDashboardResponse.queryTypeChartData.labels.indexOf(name);
                if (qIdx !== -1 && window.lastDashboardResponse.queryTypeChartData.datasets && window.lastDashboardResponse.queryTypeChartData.datasets[0]) {
                    filterVolume = window.lastDashboardResponse.queryTypeChartData.datasets[0].data[qIdx] || 0;
                    isRecordOrProtocol = true;
                    if (!cat || cat === "Breakdown") cat = "Record Type";
                }
            }
            if (filterVolume === 0 && window.lastDashboardResponse.protocolTypeChartData && window.lastDashboardResponse.protocolTypeChartData.labels) {
                var pIdx = window.lastDashboardResponse.protocolTypeChartData.labels.indexOf(name);
                if (pIdx !== -1 && window.lastDashboardResponse.protocolTypeChartData.datasets && window.lastDashboardResponse.protocolTypeChartData.datasets[0]) {
                    filterVolume = window.lastDashboardResponse.protocolTypeChartData.datasets[0].data[pIdx] || 0;
                    isRecordOrProtocol = true;
                    if (!cat || cat === "Breakdown") cat = "Protocol";
                }
            }
        }

        if (isRecordOrProtocol && filterVolume > 0 && totDs && totDs.data) {
            var ratio = totalQueriesCount > 0 ? (filterVolume / totalQueriesCount) : 0;
            var projectedData = totDs.data.map(function(v) { return Math.round(v * ratio); });
            var pctStr = (ratio * 100).toFixed(1) + "%";
            var sigColor = (cat === "Record Type") ? "#06b6d4" : "#3b82f6";

            filteredDatasets.push({
                label: (cat === "Record Type" ? "Record: " : "Protocol: ") + name + " (" + pctStr + ")",
                data: projectedData,
                borderColor: sigColor,
                backgroundColor: sigColor === "#06b6d4" ? "rgba(6, 182, 212, 0.15)" : "rgba(59, 130, 246, 0.15)",
                borderWidth: 2.5,
                fill: true,
                lineTension: 0.36,
                pointRadius: 0,
                pointHoverRadius: 5,
                hidden: false
            });

            filteredDatasets.push({
                label: "Total Queries (Reference)",
                data: totDs.data.slice(),
                borderColor: "rgba(148, 163, 184, 0.45)",
                backgroundColor: "transparent",
                borderWidth: 1.5,
                borderDash: [4, 4],
                fill: false,
                lineTension: 0.36,
                pointRadius: 0,
                pointHoverRadius: 4,
                hidden: false
            });

            $("#lblDashboardChartLegend").html(
                '<span class="legend-pill active"><span class="legend-dot" style="background:' + sigColor + ';"></span> ' + htmlEncode(name) + ' (' + pctStr + ')</span>' +
                '<span class="legend-pill active" style="margin-left: 10px; opacity: 0.85;"><span class="legend-dot" style="background:#94a3b8; border: 1px dashed #cbd5e1;"></span> Total Queries (Reference)</span>'
            );
        } else {
            // Metric matches a direct resolution or response code dataset
            var rawCopies = JSON.parse(JSON.stringify(window.lastMainChartOriginalDatasets));
            var targetNorm = name.toLowerCase().replace(/[^a-z0-9]/g, "");
            var matchedColor = "#38bdf8";

            rawCopies.forEach(function (ds) {
                var dsNorm = (ds.label || '').toLowerCase().replace(/[^a-z0-9]/g, "");
                var isTotal = (dsNorm === "total" || dsNorm === "totalqueries");
                var isDirectMatch = (dsNorm === targetNorm) ||
                                    (targetNorm === "noerror" && dsNorm === "noerror") ||
                                    (targetNorm === "nxdomain" && dsNorm === "nxdomain") ||
                                    (targetNorm === "cachedrecords" && dsNorm === "cached") ||
                                    (targetNorm === "blockedzones" && dsNorm === "blocked");

                if (isDirectMatch) {
                    ds.hidden = false;
                    ds.borderWidth = 2.5;
                    ds.fill = true;
                    matchedColor = ds.borderColor || "#10b981";
                    filteredDatasets.unshift(ds);
                } else if (isTotal) {
                    ds.hidden = false;
                    ds.fill = false;
                    ds.borderWidth = 1.5;
                    ds.borderDash = [4, 4];
                    ds.borderColor = "rgba(148, 163, 184, 0.45)";
                    ds.label = "Total Queries (Reference)";
                    filteredDatasets.push(ds);
                }
            });

            if (filteredDatasets.length === 0 && totDs) {
                filteredDatasets.push(totDs);
            }

            $("#lblDashboardChartLegend").html(
                '<span class="legend-pill active"><span class="legend-dot" style="background:' + matchedColor + ';"></span> ' + htmlEncode(name) + '</span>' +
                '<span class="legend-pill active" style="margin-left: 10px; opacity: 0.85;"><span class="legend-dot" style="background:#94a3b8; border: 1px dashed #cbd5e1;"></span> Total Queries (Reference)</span>'
            );
        }

        window.chartDashboardMain.data.datasets = filteredDatasets;
        window.chartDashboardMain.update(0);
    }
}

// --- Dynamic Population & Selection for Chart Header Filter Controls ---
function updateChartFilterMenus(resp) {
    if (!resp) return;

    // 1. Populate Record Types Filter Dropdown
    if (resp.queryTypeChartData && resp.queryTypeChartData.labels) {
        var recLabels = resp.queryTypeChartData.labels;
        var recCounts = (resp.queryTypeChartData.datasets && resp.queryTypeChartData.datasets[0]) ? resp.queryTypeChartData.datasets[0].data : [];
        var totalRec = recCounts.reduce(function (a, b) { return a + b; }, 0) || 1;

        var recItems = [];
        for (var i = 0; i < recLabels.length; i++) {
            recItems.push({ label: recLabels[i], count: recCounts[i] || 0 });
        }
        recItems.sort(function (a, b) { return b.count - a.count; });

        var activeFilter = (window.activeDashboardFilter && window.activeDashboardFilter.category === "Record Type") ? window.activeDashboardFilter.name : "All";

        var recHtml = '<li class="' + (activeFilter === "All" ? "active" : "") + '"><a href="#" onclick="selectChartRecordTypeFilter(\'All\'); return false;">' + (activeFilter === "All" ? '<i class="fa fa-check fa-fw"></i> ' : '') + 'All Record Types</a></li>';
        recHtml += '<li role="separator" class="divider"></li>';

        for (var j = 0; j < recItems.length; j++) {
            var itm = recItems[j];
            var pct = ((itm.count / totalRec) * 100).toFixed(1);
            var isSel = (activeFilter.toLowerCase() === itm.label.toLowerCase());
            recHtml += '<li class="' + (isSel ? "active" : "") + '"><a href="#" onclick="selectChartRecordTypeFilter(\'' + htmlEncode(itm.label) + '\'); return false;">' + (isSel ? '<i class="fa fa-check fa-fw"></i> ' : '') + '<b>' + htmlEncode(itm.label) + '</b> <span style="opacity: 0.65; font-size: 11px;">&bull; ' + itm.count.toLocaleString() + ' (' + pct + '%)</span></a></li>';
        }
        $("#menuFilterRecordType").html(recHtml);
    }

    // 2. Populate Protocols Filter Dropdown
    if (resp.protocolTypeChartData && resp.protocolTypeChartData.labels) {
        var protoLabels = resp.protocolTypeChartData.labels;
        var protoCounts = (resp.protocolTypeChartData.datasets && resp.protocolTypeChartData.datasets[0]) ? resp.protocolTypeChartData.datasets[0].data : [];
        var totalProto = protoCounts.reduce(function (a, b) { return a + b; }, 0) || 1;

        var protoItems = [];
        for (var k = 0; k < protoLabels.length; k++) {
            protoItems.push({ label: protoLabels[k], count: protoCounts[k] || 0 });
        }
        protoItems.sort(function (a, b) { return b.count - a.count; });

        var activeProtoFilter = (window.activeDashboardFilter && window.activeDashboardFilter.category === "Protocol") ? window.activeDashboardFilter.name : "All";

        var protoHtml = '<li class="' + (activeProtoFilter === "All" ? "active" : "") + '"><a href="#" onclick="selectChartProtocolFilter(\'All\'); return false;">' + (activeProtoFilter === "All" ? '<i class="fa fa-check fa-fw"></i> ' : '') + 'All Protocols</a></li>';
        protoHtml += '<li role="separator" class="divider"></li>';

        for (var m = 0; m < protoItems.length; m++) {
            var pItm = protoItems[m];
            var pPct = ((pItm.count / totalProto) * 100).toFixed(1);
            var isProtoSel = (activeProtoFilter.toLowerCase() === pItm.label.toLowerCase());
            protoHtml += '<li class="' + (isProtoSel ? "active" : "") + '"><a href="#" onclick="selectChartProtocolFilter(\'' + htmlEncode(pItm.label) + '\'); return false;">' + (isProtoSel ? '<i class="fa fa-check fa-fw"></i> ' : '') + '<b>' + htmlEncode(pItm.label) + '</b> <span style="opacity: 0.65; font-size: 11px;">&bull; ' + pItm.count.toLocaleString() + ' (' + pPct + '%)</span></a></li>';
        }
        $("#menuFilterProtocol").html(protoHtml);
    }
}

function selectChartRecordTypeFilter(recordType) {
    if (recordType === "All") {
        $("#lblFilterRecordType").text("Record: All");
        $("#btnFilterRecordType").removeClass("active-filter");
        clearActiveDashboardFilter();
    } else {
        $("#lblFilterRecordType").text("Record: " + recordType);
        $("#btnFilterRecordType").addClass("active-filter");
        $("#lblFilterProtocol").text("Protocol: All");
        $("#btnFilterProtocol").removeClass("active-filter");
        toggleDashboardFilter("Record Type", recordType);
    }
    if (window.lastDashboardResponse) {
        updateChartFilterMenus(window.lastDashboardResponse);
    }
}

function selectChartProtocolFilter(protocol) {
    if (protocol === "All") {
        $("#lblFilterProtocol").text("Protocol: All");
        $("#btnFilterProtocol").removeClass("active-filter");
        clearActiveDashboardFilter();
    } else {
        $("#lblFilterProtocol").text("Protocol: " + protocol);
        $("#btnFilterProtocol").addClass("active-filter");
        $("#lblFilterRecordType").text("Record: All");
        $("#btnFilterRecordType").removeClass("active-filter");
        toggleDashboardFilter("Protocol", protocol);
    }
    if (window.lastDashboardResponse) {
        updateChartFilterMenus(window.lastDashboardResponse);
    }
}

function updateChart(chart, data) {
    chart.data = data;
    chart.update(0);
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
    localStorage.setItem("dashboardClusterNode", node);

    if (!hideLoader) {
        divDashboard.hide();
        divDashboardLoader.show();
    }

    HTTPRequest({
        url: "api/dashboard/stats/get?type=" + type + "&utc=true" + custom + "&node=" + encodeURIComponent(node),
        token: sessionData.token,
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

            // Zone & Cache Overview Stats
            $("#divDashboardStatsZones").text(responseJSON.response.stats.zones.toLocaleString());
            $("#divDashboardStatsCachedEntries").text(responseJSON.response.stats.cachedEntries.toLocaleString());
            $("#divDashboardStatsAllowedZones").text(responseJSON.response.stats.allowedZones.toLocaleString());
            $("#divDashboardStatsBlockedZones").text(responseJSON.response.stats.blockedZones.toLocaleString());
            $("#divDashboardStatsAllowListZones").text(responseJSON.response.stats.allowListZones.toLocaleString());
            $("#divDashboardStatsBlockListZones").text(responseJSON.response.stats.blockListZones.toLocaleString());

            // Calculated Error Metrics (ServFail + Refused + Dropped)
            var totalErrors = responseJSON.response.stats.totalServerFailure + responseJSON.response.stats.totalRefused + responseJSON.response.stats.totalDropped;
            $("#divDashboardStatsTotalErrors").text(totalErrors.toLocaleString());

            // Calculated QPS
            var secondsInInterval = 3600;
            switch (type) {
                case "lastHour": secondsInInterval = 3600; break;
                case "lastDay": secondsInInterval = 86400; break;
                case "lastWeek": secondsInInterval = 604800; break;
                case "lastMonth": secondsInInterval = 2592000; break;
                case "lastYear": secondsInInterval = 31536000; break;
                default: secondsInInterval = 86400; break;
            }
            var qps = (responseJSON.response.stats.totalQueries / secondsInInterval).toFixed(1);
            $("#divDashboardStatsQPS").text("~" + qps + " QPS");

            if (responseJSON.response.stats.totalQueries > 0) {
                $("#divDashboardStatsTotalNoErrorPercentage").text((responseJSON.response.stats.totalNoError * 100 / responseJSON.response.stats.totalQueries).toFixed(2) + "%");
                $("#divDashboardStatsTotalServerFailurePercentage").text((responseJSON.response.stats.totalServerFailure * 100 / responseJSON.response.stats.totalQueries).toFixed(2) + "%");
                $("#divDashboardStatsTotalNxDomainPercentage").text((responseJSON.response.stats.totalNxDomain * 100 / responseJSON.response.stats.totalQueries).toFixed(2) + "%");
                $("#divDashboardStatsTotalRefusedPercentage").text((responseJSON.response.stats.totalRefused * 100 / responseJSON.response.stats.totalQueries).toFixed(2) + "%");
                $("#divDashboardStatsTotalErrorsPercentage").text((totalErrors * 100 / responseJSON.response.stats.totalQueries).toFixed(2) + "%");

                $("#divDashboardStatsTotalAuthHitPercentage").text((responseJSON.response.stats.totalAuthoritative * 100 / responseJSON.response.stats.totalQueries).toFixed(2) + "%");
                $("#divDashboardStatsTotalRecursionsPercentage").text((responseJSON.response.stats.totalRecursive * 100 / responseJSON.response.stats.totalQueries).toFixed(1) + "%");
                $("#divDashboardStatsTotalCacheHitPercentage").text((responseJSON.response.stats.totalCached * 100 / responseJSON.response.stats.totalQueries).toFixed(2) + "%");
                $("#divDashboardStatsTotalBlockedPercentage").text((responseJSON.response.stats.totalBlocked * 100 / responseJSON.response.stats.totalQueries).toFixed(2) + "%");
                $("#divDashboardStatsTotalDroppedPercentage").text((responseJSON.response.stats.totalDropped * 100 / responseJSON.response.stats.totalQueries).toFixed(2) + "%");

                // Analytical Matrix - Response Codes (Calculated percentages)
                var pctMatrixNoError = (responseJSON.response.stats.totalNoError * 100 / responseJSON.response.stats.totalQueries).toFixed(1);
                var pctMatrixNxDomain = (responseJSON.response.stats.totalNxDomain * 100 / responseJSON.response.stats.totalQueries).toFixed(1);
                var pctMatrixServFail = (responseJSON.response.stats.totalServerFailure * 100 / responseJSON.response.stats.totalQueries).toFixed(1);
                var pctMatrixRefused = (responseJSON.response.stats.totalRefused * 100 / responseJSON.response.stats.totalQueries).toFixed(1);

                // Dynamic Descending Sort & Render for Response Codes
                var responseCodesData = [
                    { label: "No Error", count: responseJSON.response.stats.totalNoError, pct: pctMatrixNoError, barClass: "bar-emerald" },
                    { label: "NX Domain", count: responseJSON.response.stats.totalNxDomain, pct: pctMatrixNxDomain, barClass: "bar-amber" },
                    { label: "Server Failure", count: responseJSON.response.stats.totalServerFailure, pct: pctMatrixServFail, barClass: "bar-crimson" },
                    { label: "Refused", count: responseJSON.response.stats.totalRefused, pct: pctMatrixRefused, barClass: "bar-purple" }
                ];
                responseCodesData.sort(function (a, b) { return b.count - a.count; });
                var respHtml = "";
                for (var r = 0; r < responseCodesData.length; r++) {
                    var itm = responseCodesData[r];
                    var isLast = r === responseCodesData.length - 1 ? ' style="margin-bottom: 0;"' : '';
                    respHtml += '<div class="matrix-metric-row clickable-filter-row" data-filter-name="' + itm.label + '" onclick="toggleDashboardFilter(\'Response Code\', \'' + itm.label + '\');"' + isLast + '>';
                    respHtml += '  <div class="matrix-metric-header">';
                    respHtml += '    <span>' + itm.label + '</span>';
                    respHtml += '    <span class="matrix-metric-val">' + itm.count.toLocaleString() + ' (' + itm.pct + '%)</span>';
                    respHtml += '  </div>';
                    respHtml += '  <div class="matrix-bar-track">';
                    respHtml += '    <div class="matrix-bar-fill ' + itm.barClass + '" style="width: ' + itm.pct + '%;"></div>';
                    respHtml += '  </div>';
                    respHtml += '</div>';
                }
                $("#containerMatrixResponseCodes").html(respHtml);

                // Analytical Matrix - Resolution Types (Calculated percentages)
                var pctMatrixRecursive = (responseJSON.response.stats.totalRecursive * 100 / responseJSON.response.stats.totalQueries).toFixed(1);
                var pctMatrixCached = (responseJSON.response.stats.totalCached * 100 / responseJSON.response.stats.totalQueries).toFixed(1);
                var pctMatrixAuth = (responseJSON.response.stats.totalAuthoritative * 100 / responseJSON.response.stats.totalQueries).toFixed(1);
                var pctMatrixDropped = (responseJSON.response.stats.totalDropped * 100 / responseJSON.response.stats.totalQueries).toFixed(1);

                // Dynamic Descending Sort & Render for Resolution Types
                var resolutionTypesData = [
                    { label: "Cached", count: responseJSON.response.stats.totalCached, pct: pctMatrixCached, barClass: "bar-emerald" },
                    { label: "Recursive", count: responseJSON.response.stats.totalRecursive, pct: pctMatrixRecursive, barClass: "bar-blue" },
                    { label: "Authoritative", count: responseJSON.response.stats.totalAuthoritative, pct: pctMatrixAuth, barClass: "bar-teal" },
                    { label: "Dropped", count: responseJSON.response.stats.totalDropped, pct: pctMatrixDropped, barClass: "bar-slate" }
                ];
                resolutionTypesData.sort(function (a, b) { return b.count - a.count; });
                var resolHtml = "";
                for (var s = 0; s < resolutionTypesData.length; s++) {
                    var itm = resolutionTypesData[s];
                    var isLast = s === resolutionTypesData.length - 1 ? ' style="margin-bottom: 0;"' : '';
                    resolHtml += '<div class="matrix-metric-row clickable-filter-row" data-filter-name="' + itm.label + '" onclick="toggleDashboardFilter(\'Resolution Type\', \'' + itm.label + '\');"' + isLast + '>';
                    resolHtml += '  <div class="matrix-metric-header">';
                    resolHtml += '    <span>' + itm.label + '</span>';
                    resolHtml += '    <span class="matrix-metric-val">' + itm.count.toLocaleString() + ' (' + itm.pct + '%)</span>';
                    resolHtml += '  </div>';
                    resolHtml += '  <div class="matrix-bar-track">';
                    resolHtml += '    <div class="matrix-bar-fill ' + itm.barClass + '" style="width: ' + itm.pct + '%;"></div>';
                    resolHtml += '  </div>';
                    resolHtml += '</div>';
                }
                $("#containerMatrixResolutionTypes").html(resolHtml);
            }
            else {
                $("#divDashboardStatsTotalNoErrorPercentage").text("0%");
                $("#divDashboardStatsTotalServerFailurePercentage").text("0%");
                $("#divDashboardStatsTotalNxDomainPercentage").text("0%");
                $("#divDashboardStatsTotalRefusedPercentage").text("0%");
                $("#divDashboardStatsTotalErrorsPercentage").text("0%");

                $("#divDashboardStatsTotalAuthHitPercentage").text("0%");
                $("#divDashboardStatsTotalRecursionsPercentage").text("0%");
                $("#divDashboardStatsTotalCacheHitPercentage").text("0%");
                $("#divDashboardStatsTotalBlockedPercentage").text("0%");
                $("#divDashboardStatsTotalDroppedPercentage").text("0%");

                $("#lblMatrixNoError").text("0 (0.0%)");
                $("#barMatrixNoError").css("width", "0%");
                $("#lblMatrixNxDomain").text("0 (0.0%)");
                $("#barMatrixNxDomain").css("width", "0%");
                $("#lblMatrixServFail").text("0 (0.0%)");
                $("#barMatrixServFail").css("width", "0%");
                $("#lblMatrixRefused").text("0 (0.0%)");
                $("#barMatrixRefused").css("width", "0%");

                $("#lblMatrixRecursive").text("0 (0.0%)");
                $("#barMatrixRecursive").css("width", "0%");
                $("#lblMatrixCached").text("0 (0.0%)");
                $("#barMatrixCached").css("width", "0%");
                $("#lblMatrixAuth").text("0 (0.0%)");
                $("#barMatrixAuth").css("width", "0%");
                $("#lblMatrixDropped").text("0 (0.0%)");
                $("#barMatrixDropped").css("width", "0%");
            }

            // Analytical Matrix - Zone & Cache Overview (Universal Descending Sort & Cross-Filtering)
            var zoneStats = responseJSON.response.stats;
            var maxZoneVal = Math.max(zoneStats.cachedEntries, zoneStats.zones, zoneStats.allowedZones, zoneStats.blockedZones, 1);
            var zoneTelemetryData = [
                { label: "Cached Records", count: zoneStats.cachedEntries, spanId: "divDashboardStatsTotalCachedEntries", pct: Math.round((zoneStats.cachedEntries / maxZoneVal) * 100), barClass: "bar-emerald" },
                { label: "Blocked Zones", count: zoneStats.blockedZones, spanId: "divDashboardStatsTotalBlockedZones", pct: Math.round((zoneStats.blockedZones / maxZoneVal) * 100), barClass: "bar-amber" },
                { label: "Allowed Zones", count: zoneStats.allowedZones, spanId: "divDashboardStatsTotalAllowed", pct: Math.round((zoneStats.allowedZones / maxZoneVal) * 100), barClass: "bar-teal" },
                { label: "Authoritative Zones", count: zoneStats.zones, spanId: "divDashboardStatsTotalZones", pct: Math.round((zoneStats.zones / maxZoneVal) * 100), barClass: "bar-blue" }
            ];
            zoneTelemetryData.sort(function (a, b) { return b.count - a.count; });
            var zoneHtml = "";
            for (var z = 0; z < zoneTelemetryData.length; z++) {
                var itm = zoneTelemetryData[z];
                var isLast = z === zoneTelemetryData.length - 1 ? ' style="margin-bottom: 0;"' : '';
                zoneHtml += '<div class="matrix-metric-row clickable-filter-row" data-filter-name="' + itm.label + '" onclick="toggleDashboardFilter(\'Zone Telemetry\', \'' + itm.label + '\');"' + isLast + '>';
                zoneHtml += '  <div class="matrix-metric-header">';
                zoneHtml += '    <span>' + itm.label + '</span>';
                zoneHtml += '    <span class="matrix-metric-val"><span id="' + itm.spanId + '">' + itm.count.toLocaleString() + '</span></span>';
                zoneHtml += '  </div>';
                zoneHtml += '  <div class="matrix-bar-track">';
                zoneHtml += '    <div class="matrix-bar-fill ' + itm.barClass + '" style="width: ' + Math.max(itm.pct, itm.pct > 0 ? 3 : 0) + '%;"></div>';
                zoneHtml += '  </div>';
                zoneHtml += '</div>';
            }
            $("#containerMatrixZoneTelemetry").html(zoneHtml);

            //main chart
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

            // Save original datasets for Power BI cross-filtering
            window.lastMainChartOriginalDatasets = JSON.parse(JSON.stringify(responseJSON.response.mainChartData.datasets));

            // Modernize main chart datasets (Unstacked Modern Telemetry Lines)
            var isDarkTheme = document.body.classList.contains("dark-mode") || document.body.classList.contains("dark-grey-mode") || document.body.classList.contains("amber-mode");
            var canvasElem = document.getElementById("canvasDashboardMain");
            if (canvasElem) {
                var ctxMain = canvasElem.getContext('2d');

                var gradSky = ctxMain.createLinearGradient(0, 0, 0, 340);
                gradSky.addColorStop(0, isDarkTheme ? 'rgba(56, 189, 248, 0.16)' : 'rgba(2, 132, 199, 0.12)');
                gradSky.addColorStop(1, 'rgba(56, 189, 248, 0.01)');

                var gradEmerald = ctxMain.createLinearGradient(0, 0, 0, 340);
                gradEmerald.addColorStop(0, isDarkTheme ? 'rgba(16, 185, 129, 0.14)' : 'rgba(16, 185, 129, 0.10)');
                gradEmerald.addColorStop(1, 'rgba(16, 185, 129, 0.01)');

                var gradAmber = ctxMain.createLinearGradient(0, 0, 0, 340);
                gradAmber.addColorStop(0, isDarkTheme ? 'rgba(245, 158, 11, 0.14)' : 'rgba(217, 119, 6, 0.10)');
                gradAmber.addColorStop(1, 'rgba(245, 158, 11, 0.01)');

                responseJSON.response.mainChartData.datasets.forEach(function (ds) {
                    ds.pointRadius = 0;
                    ds.pointHoverRadius = 5;
                    ds.pointHitRadius = 8;
                    ds.lineTension = 0.36;

                    var lbl = (ds.label || '').toLowerCase();
                    if (lbl === "total" || lbl === "total queries") {
                        ds.label = "Total Queries";
                        ds.borderColor = isDarkTheme ? "#38bdf8" : "#0284c7"; // Sky Blue
                        ds.backgroundColor = gradSky;
                        ds.borderWidth = 2.5;
                        ds.fill = true;
                        ds.hidden = false;
                    } else if (lbl.indexOf("cache") !== -1) {
                        ds.label = "Cached";
                        ds.borderColor = "#10b981"; // Emerald
                        ds.backgroundColor = gradEmerald;
                        ds.borderWidth = 2;
                        ds.fill = true;
                        ds.hidden = false;
                    } else if (lbl.indexOf("recurs") !== -1) {
                        ds.label = "Recursive";
                        ds.borderColor = "#6366f1"; // Indigo
                        ds.backgroundColor = "transparent";
                        ds.borderWidth = 2;
                        ds.fill = false;
                        ds.hidden = false;
                    } else if (lbl.indexOf("block") !== -1) {
                        ds.label = "Blocked";
                        ds.borderColor = "#f59e0b"; // Amber
                        ds.backgroundColor = gradAmber;
                        ds.borderWidth = 2;
                        ds.fill = true;
                        ds.hidden = false;
                    } else if (lbl.indexOf("author") !== -1) {
                        ds.label = "Authoritative";
                        ds.borderColor = "#8b5cf6"; // Violet
                        ds.backgroundColor = "transparent";
                        ds.borderWidth = 1.8;
                        ds.fill = false;
                        ds.hidden = false;
                    } else if (lbl.indexOf("no error") !== -1 || lbl === "noerror") {
                        ds.label = "No Error";
                        ds.borderColor = "#22c55e"; // Vibrant Green
                        ds.backgroundColor = "transparent";
                        ds.borderWidth = 1.8;
                        ds.fill = false;
                        ds.hidden = false;
                    } else if (lbl.indexOf("nx") !== -1) {
                        ds.label = "NX Domain";
                        ds.borderColor = "#ec4899"; // Pink
                        ds.backgroundColor = "transparent";
                        ds.borderWidth = 1.8;
                        ds.fill = false;
                        ds.hidden = false;
                    } else if (lbl.indexOf("fail") !== -1) {
                        ds.label = "Server Failure";
                        ds.borderColor = "#ef4444"; // Crimson
                        ds.backgroundColor = "transparent";
                        ds.borderWidth = 1.8;
                        ds.fill = false;
                        ds.hidden = false;
                    } else if (lbl.indexOf("refus") !== -1) {
                        ds.label = "Refused";
                        ds.borderColor = "#a855f7"; // Purple
                        ds.backgroundColor = "transparent";
                        ds.borderWidth = 1.8;
                        ds.fill = false;
                        ds.hidden = false;
                    } else if (lbl.indexOf("drop") !== -1) {
                        ds.label = "Dropped";
                        ds.borderColor = "#64748b"; // Slate
                        ds.backgroundColor = "transparent";
                        ds.borderWidth = 1.8;
                        ds.fill = false;
                        ds.hidden = false;
                    } else if (lbl.indexOf("client") !== -1) {
                        ds.label = "Clients";
                        ds.borderColor = "#06b6d4"; // Cyan
                        ds.backgroundColor = "transparent";
                        ds.borderWidth = 1.8;
                        ds.fill = false;
                        ds.hidden = false;
                    } else {
                        ds.borderWidth = 1.8;
                        ds.fill = false;
                        ds.hidden = false;
                    }
                });
            }

            if (window.chartDashboardMain == null) {
                var contextDashboardMain = document.getElementById("canvasDashboardMain").getContext('2d');

                window.chartDashboardMain = new Chart(contextDashboardMain, {
                    type: 'line',
                    data: responseJSON.response.mainChartData,
                    options: {
                        elements: {
                            line: {
                                tension: 0.36
                            }
                        },
                        scales: {
                            yAxes: [{
                                stacked: false,
                                ticks: {
                                    beginAtZero: true,
                                    fontColor: isDarkTheme ? "#94a3b8" : "#64748b"
                                },
                                gridLines: {
                                    color: isDarkTheme ? "rgba(255, 255, 255, 0.04)" : "rgba(0, 0, 0, 0.04)",
                                    zeroLineColor: isDarkTheme ? "rgba(255, 255, 255, 0.08)" : "rgba(0, 0, 0, 0.08)"
                                }
                            }],
                            xAxes: [{
                                stacked: false,
                                gridLines: {
                                    color: isDarkTheme ? "rgba(255, 255, 255, 0.03)" : "rgba(0, 0, 0, 0.03)",
                                    zeroLineColor: isDarkTheme ? "rgba(255, 255, 255, 0.06)" : "rgba(0, 0, 0, 0.06)"
                                }
                            }]
                        },
                        tooltips: {
                            enabled: true,
                            mode: 'index',
                            intersect: false,
                            backgroundColor: isDarkTheme ? 'rgba(15, 23, 42, 0.94)' : 'rgba(255, 255, 255, 0.96)',
                            titleFontColor: isDarkTheme ? '#f8fafc' : '#0f172a',
                            titleFontSize: 12,
                            titleFontStyle: '600',
                            bodyFontColor: isDarkTheme ? '#e2e8f0' : '#334155',
                            bodyFontSize: 11,
                            borderColor: isDarkTheme ? 'rgba(255, 255, 255, 0.12)' : 'rgba(0, 0, 0, 0.12)',
                            borderWidth: 1,
                            cornerRadius: 8,
                            caretSize: 6,
                            xPadding: 12,
                            yPadding: 10,
                            callbacks: {
                                title: function (tooltipItems, data) {
                                    if (!tooltipItems.length) return "";
                                    var timeLabel = tooltipItems[0].xLabel || "";
                                    var totVal = null;
                                    tooltipItems.forEach(function (ti) {
                                        var ds = data.datasets[ti.datasetIndex];
                                        if (ds && (ds.label === "Total Queries" || ds.label === "Total" || ds.label === "Total Queries (Reference)")) {
                                            totVal = Number(ti.yLabel) || 0;
                                        }
                                    });
                                    return timeLabel + (totVal !== null ? "  •  Total: " + totVal.toLocaleString() + " queries" : "");
                                },
                                label: function (tooltipItem, data) {
                                    var ds = data.datasets[tooltipItem.datasetIndex];
                                    if (!ds || ds.hidden) return null;
                                    var val = tooltipItem.yLabel != null ? Number(tooltipItem.yLabel) : 0;
                                    return ' ' + (ds.label || '') + ': ' + val.toLocaleString();
                                }
                            }
                        },
                        legend: {
                            display: false
                        }
                    }
                });
            }
            else {
                updateChart(window.chartDashboardMain, responseJSON.response.mainChartData);
            }

            renderMainChartLegend();

            // Re-apply active cross-filtering if active
            if (window.activeDashboardFilter && typeof applyActiveDashboardFilter === "function") {
                applyActiveDashboardFilter();
            }

            // Save response for sub-view chart switching
            window.lastDashboardResponse = responseJSON.response;
            updateChartFilterMenus(responseJSON.response);

            // Live QPS dynamic delta calculation
            var nowTick = Date.now();
            var currentTotalQ = responseJSON.response.stats.totalQueries;
            if (window.lastAutoRefreshTime > 0 && window.lastAutoRefreshTotalQueries >= 0 && currentTotalQ >= window.lastAutoRefreshTotalQueries) {
                var deltaQ = currentTotalQ - window.lastAutoRefreshTotalQueries;
                var deltaS = (nowTick - window.lastAutoRefreshTime) / 1000.0;
                if (deltaS > 0) {
                    var liveQps = (deltaQ / deltaS).toFixed(1);
                    $("#divDashboardStatsQPS").html('<i class="fa fa-bolt" style="color: #f59e0b; font-size:10px; margin-right: 5px;"></i> ~' + liveQps + ' QPS &nbsp;<span style="font-size:10px; opacity:0.75;">(live)</span>');
                }
            }
            window.lastAutoRefreshTime = nowTick;
            window.lastAutoRefreshTotalQueries = currentTotalQ;

            // Render/Update the currently active sub-view chart
            var currentSubView = localStorage.getItem("dashboard_chart_subview") || "traffic";
            if (typeof renderOrUpdateSubViewChart === "function") {
                renderOrUpdateSubViewChart(currentSubView);
            }

            // --- Modern Curated Color Palettes for Donut Charts ---
            var QUERY_RESPONSE_COLORS = {
                "Cached": "#10b981",        // Emerald Green (Instant Hit)
                "Recursive": "#3b82f6",     // Electric Blue (Upstream Query)
                "Authoritative": "#8b5cf6", // Violet (Local Zone Hit)
                "Blocked": "#f97316",       // Vivid Amber/Orange (Filtered)
                "Dropped": "#ef4444"        // Coral Red (Security Drop)
            };

            var RECORD_TYPE_COLORS = {
                "A": "#3b82f6",             // Blue
                "AAAA": "#10b981",          // Emerald
                "HTTPS": "#8b5cf6",         // Purple
                "TXT": "#f59e0b",           // Amber
                "PTR": "#06b6d4",           // Cyan
                "SRV": "#ec4899",           // Pink
                "CNAME": "#6366f1",         // Indigo
                "MX": "#14b8a6",            // Teal
                "SOA": "#64748b",           // Slate
                "NS": "#0284c7"             // Sky
            };

            var PROTOCOL_TYPE_COLORS = {
                "Udp": "#3b82f6",           // Modern Blue
                "Tcp": "#6366f1",           // Indigo
                "Tls": "#10b981",           // Emerald (Encrypted DNS-over-TLS)
                "Https": "#8b5cf6",         // Violet (Encrypted DNS-over-HTTPS)
                "Quic": "#06b6d4"           // Cyan (DNS-over-QUIC / HTTP/3)
            };

            var FALLBACK_MODERN_PALETTE = [
                "#3b82f6", "#10b981", "#8b5cf6", "#f59e0b", "#06b6d4",
                "#ec4899", "#6366f1", "#14b8a6", "#f97316", "#64748b"
            ];

            function renderModernDonut(chartVarName, canvasId, chartData, colorMap, fallbackPalette, totalPillId, centerValId, listId, category) {
                var canvas = document.getElementById(canvasId);
                if (!canvas) return;

                var labels = (chartData && chartData.labels) ? chartData.labels : [];
                var rawValues = (chartData && chartData.datasets && chartData.datasets[0] && chartData.datasets[0].data) ? chartData.datasets[0].data : [];

                // 1. Compute totals and items
                var total = 0;
                var items = [];
                for (var i = 0; i < labels.length; i++) {
                    var val = rawValues[i] != null ? Number(rawValues[i]) : 0;
                    total += val;
                    var lbl = labels[i];
                    var col = (colorMap && colorMap[lbl]) ? colorMap[lbl] : fallbackPalette[i % fallbackPalette.length];
                    items.push({
                        label: lbl,
                        value: val,
                        color: col
                    });
                }

                // 2. Update Header Total Pill & Donut Center Stat
                if (totalPillId) {
                    $("#" + totalPillId).text(total.toLocaleString() + " total");
                }
                if (centerValId) {
                    var displayCenter = total >= 1000000 ? (total / 1000000).toFixed(1) + "M" : total >= 1000 ? (total / 1000).toFixed(1) + "k" : total.toLocaleString();
                    $("#" + centerValId).text(displayCenter);
                }

                // 3. Sort items descending by traffic for the breakdown list
                var sortedItems = items.slice().sort(function (a, b) { return b.value - a.value; });

                // 4. Render Rich Breakdown List (visible at a glance, no cursor hover needed!)
                var listHtml = "";
                var filterCat = category || "Breakdown";
                if (items.length === 0 || total === 0) {
                    listHtml = "<div style=\"text-align: center; padding: 12px; font-size: 11px; opacity: 0.6;\">No activity recorded</div>";
                } else {
                    for (var j = 0; j < sortedItems.length; j++) {
                        var it = sortedItems[j];
                        var pct = total > 0 ? ((it.value / total) * 100).toFixed(1) : "0.0";
                        listHtml += "<div class=\"breakdown-row clickable-filter-row\" data-filter-name=\"" + htmlEncode(it.label) + "\" onclick=\"toggleDashboardFilter('" + filterCat + "', '" + htmlEncode(it.label) + "');\" style=\"cursor: pointer;\">";
                        listHtml += "  <div class=\"breakdown-header-line\">";
                        listHtml += "    <div class=\"breakdown-label-wrap\">";
                        listHtml += "      <span class=\"breakdown-color-dot\" style=\"background-color: " + it.color + "; color: " + it.color + ";\"></span>";
                        listHtml += "      <span class=\"breakdown-name\" title=\"" + htmlEncode(it.label) + "\">" + htmlEncode(it.label) + "</span>";
                        listHtml += "    </div>";
                        listHtml += "    <div class=\"breakdown-values-wrap\">";
                        listHtml += "      <span class=\"breakdown-count\">" + it.value.toLocaleString() + "</span>";
                        listHtml += "      <span class=\"breakdown-pct-tag\" style=\"background: " + it.color + "20; color: " + it.color + "; border: 1px solid " + it.color + "40;\">" + pct + "%</span>";
                        listHtml += "    </div>";
                        listHtml += "  </div>";
                        listHtml += "  <div class=\"breakdown-track\"><div class=\"breakdown-fill\" style=\"width: " + pct + "%; background-color: " + it.color + ";\"></div></div>";
                        listHtml += "</div>";
                    }
                }
                if (listId) {
                    $("#" + listId).html(listHtml);
                }

                // 5. Build Doughnut Chart with crisp slice borders and hover animations
                var isDark = document.body.classList.contains("dark-mode");
                var sliceBorderColor = isDark ? "#1e293b" : "#ffffff";
                var bgColors = items.map(function (x) { return x.color; });

                var modernChartData = {
                    labels: labels,
                    datasets: [{
                        data: rawValues,
                        backgroundColor: bgColors,
                        borderColor: sliceBorderColor,
                        borderWidth: 2.5,
                        hoverBorderColor: sliceBorderColor,
                        hoverBorderWidth: 3
                    }]
                };

                var chartOptions = {
                    cutoutPercentage: 72,
                    responsive: true,
                    maintainAspectRatio: false,
                    legend: {
                        display: false // Replaced by rich interactive breakdown list
                    },
                    tooltips: {
                        callbacks: {
                            label: function (tooltipItem, data) {
                                var ds = data.datasets[tooltipItem.datasetIndex];
                                var currentVal = ds.data[tooltipItem.index] || 0;
                                var pct = total > 0 ? ((currentVal / total) * 100).toFixed(1) : "0.0";
                                var currentLabel = data.labels[tooltipItem.index] || "";
                                return " " + currentLabel + ": " + currentVal.toLocaleString() + " (" + pct + "%)";
                            }
                        }
                    },
                    onClick: function (evt, elements) {
                        if (elements && elements.length > 0) {
                            var clickedIdx = elements[0]._index;
                            var clickedLabel = modernChartData.labels[clickedIdx];
                            if (clickedLabel) {
                                toggleDashboardFilter(filterCat, clickedLabel);
                            }
                        }
                    },
                    animation: {
                        animateRotate: true,
                        animateScale: false
                    }
                };

                if (window[chartVarName] == null) {
                    var ctx = canvas.getContext('2d');
                    window[chartVarName] = new Chart(ctx, {
                        type: 'doughnut',
                        data: modernChartData,
                        options: chartOptions
                    });
                } else {
                    window[chartVarName].data = modernChartData;
                    window[chartVarName].options.legend.display = false;
                    window[chartVarName].options.cutoutPercentage = 72;
                    window[chartVarName].options.onClick = chartOptions.onClick;
                    window[chartVarName].options.animation = false;
                    window[chartVarName].update(0);
                }
            }

            // Render all 3 distribution analytics cards with category-aware cross-filtering
            renderModernDonut("chartDashboardPie", "canvasDashboardPie", responseJSON.response.queryResponseChartData, QUERY_RESPONSE_COLORS, FALLBACK_MODERN_PALETTE, "lblTotalResponses", "lblCenterResponsesVal", "listBreakdownResponses", "Response");
            renderModernDonut("chartDashboardPie2", "canvasDashboardPie2", responseJSON.response.queryTypeChartData, RECORD_TYPE_COLORS, FALLBACK_MODERN_PALETTE, "lblTotalRecordTypes", "lblCenterRecordTypesVal", "listBreakdownRecordTypes", "Record Type");
            renderModernDonut("chartDashboardPie3", "canvasDashboardPie3", responseJSON.response.protocolTypeChartData, PROTOCOL_TYPE_COLORS, FALLBACK_MODERN_PALETTE, "lblTotalProtocols", "lblCenterProtocolsVal", "listBreakdownProtocols", "Protocol");

            //top clients (with Proportional Progress Bars & Rank Badges)
            {
                var tableHtmlRows;
                var topClients = responseJSON.response.topClients;

                if (topClients.length < 1) {
                    tableHtmlRows = "<tr><td colspan=\"4\" align=\"center\" style=\"padding: 16px; opacity: 0.6;\">No Client Data Available</td></tr>";
                }
                else {
                    tableHtmlRows = "";
                    var maxClientHits = topClients[0].hits > 0 ? topClients[0].hits : 1;

                    for (var i = 0; i < topClients.length; i++) {
                        var rank = i + 1;
                        var rankClass = rank <= 3 ? " rank-" + rank : "";
                        var percentOfMax = Math.min(100, Math.round((topClients[i].hits / maxClientHits) * 100));
                        var clientName = htmlEncode(topClients[i].name) + (topClients[i].rateLimited ? " <span class=\"label label-warning\" style=\"font-size: 10px;\">Rate Limited</span>" : "");
                        var hostDomain = (topClients[i].domain && topClients[i].domain !== "") ? ("<div style=\"font-size: 11px; opacity: 0.75;\">" + htmlEncode(topClients[i].domain) + "</div>") : "";

                        tableHtmlRows += "<tr" + (topClients[i].rateLimited ? " style=\"color: #f59e0b;\"" : "") + ">";
                        tableHtmlRows += "<td style=\"vertical-align: middle;\"><span class=\"rank-badge" + rankClass + "\">#" + rank + "</span></td>";
                        tableHtmlRows += "<td style=\"word-wrap: anywhere;\"><strong>" + clientName + "</strong>" + hostDomain;
                        tableHtmlRows += "<div class=\"stat-progress-bar\"><div class=\"stat-progress-fill fill-primary\" style=\"width: " + percentOfMax + "%;\"></div></div>";
                        tableHtmlRows += "</td>";
                        tableHtmlRows += "<td style=\"vertical-align: middle;\"><strong>" + topClients[i].hits.toLocaleString() + "</strong> <span style=\"font-size: 11px; opacity: 0.7;\">(" + percentOfMax + "%)</span></td>";
                        tableHtmlRows += "<td align=\"right\" style=\"vertical-align: middle;\"><div class=\"dropdown\"><a href=\"#\" id=\"btnDashboardTopClientsRowOption" + i + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\" style=\"color: inherit; opacity: 0.7;\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"showQueryLogs(null, '" + topClients[i].name + "', '" + node + "'); return false;\"><i class=\"fa fa-list\"></i> Show Query Logs</a></li>";
                        tableHtmlRows += "</ul></div></td></tr>";
                    }
                }

                $("#tableTopClients").html(tableHtmlRows);
            }

            //top domains (with Proportional Progress Bars & Rank Badges)
            {
                var tableHtmlRows;
                var topDomains = responseJSON.response.topDomains;

                if (topDomains.length < 1) {
                    tableHtmlRows = "<tr><td colspan=\"4\" align=\"center\" style=\"padding: 16px; opacity: 0.6;\">No Domain Data Available</td></tr>";
                }
                else {
                    tableHtmlRows = "";
                    var maxDomainHits = topDomains[0].hits > 0 ? topDomains[0].hits : 1;

                    for (var i = 0; i < topDomains.length; i++) {
                        var rank = i + 1;
                        var rankClass = rank <= 3 ? " rank-" + rank : "";
                        var percentOfMax = Math.min(100, Math.round((topDomains[i].hits / maxDomainHits) * 100));
                        var domainName = htmlEncode(topDomains[i].nameIdn ? topDomains[i].nameIdn : (topDomains[i].name === "" ? "." : topDomains[i].name));

                        tableHtmlRows += "<tr>";
                        tableHtmlRows += "<td style=\"vertical-align: middle;\"><span class=\"rank-badge" + rankClass + "\">#" + rank + "</span></td>";
                        tableHtmlRows += "<td style=\"word-wrap: anywhere;\"><strong>" + domainName + "</strong>";
                        tableHtmlRows += "<div class=\"stat-progress-bar\"><div class=\"stat-progress-fill fill-primary\" style=\"width: " + percentOfMax + "%;\"></div></div>";
                        tableHtmlRows += "</td>";
                        tableHtmlRows += "<td style=\"vertical-align: middle;\"><strong>" + topDomains[i].hits.toLocaleString() + "</strong> <span style=\"font-size: 11px; opacity: 0.7;\">(" + percentOfMax + "%)</span></td>";
                        tableHtmlRows += "<td align=\"right\" style=\"vertical-align: middle;\"><div class=\"dropdown\"><a href=\"#\" id=\"btnDashboardTopDomainsRowOption" + i + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\" style=\"color: inherit; opacity: 0.7;\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"showQueryLogs('" + topDomains[i].name + "', null, '" + node + "'); return false;\"><i class=\"fa fa-list\"></i> Show Query Logs</a></li>";
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"queryDnsServer('" + topDomains[i].name + "', null, '" + node + "'); return false;\"><i class=\"fa fa-search\"></i> Query DNS Server</a></li>";
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" data-domain=\"" + htmlEncode(topDomains[i].name) + "\" onclick=\"blockDomain(this, 'btnDashboardTopDomainsRowOption'); return false;\"><i class=\"fa fa-ban\"></i> Block Domain</a></li>";
                        tableHtmlRows += "</ul></div></td></tr>";
                    }
                }

                $("#tableTopDomains").html(tableHtmlRows);
            }

            //top blocked domains (with Proportional Progress Bars & Rank Badges)
            {
                var tableHtmlRows;
                var topBlockedDomains = responseJSON.response.topBlockedDomains;

                if (topBlockedDomains.length < 1) {
                    tableHtmlRows = "<tr><td colspan=\"4\" align=\"center\" style=\"padding: 16px; opacity: 0.6;\">No Blocked Domain Data</td></tr>";
                }
                else {
                    tableHtmlRows = "";
                    var maxBlockedHits = topBlockedDomains[0].hits > 0 ? topBlockedDomains[0].hits : 1;

                    for (var i = 0; i < topBlockedDomains.length; i++) {
                        var rank = i + 1;
                        var rankClass = rank <= 3 ? " rank-" + rank : "";
                        var percentOfMax = Math.min(100, Math.round((topBlockedDomains[i].hits / maxBlockedHits) * 100));
                        var domainName = htmlEncode(topBlockedDomains[i].nameIdn ? topBlockedDomains[i].nameIdn : (topBlockedDomains[i].name === "" ? "." : topBlockedDomains[i].name));

                        tableHtmlRows += "<tr>";
                        tableHtmlRows += "<td style=\"vertical-align: middle;\"><span class=\"rank-badge" + rankClass + "\">#" + rank + "</span></td>";
                        tableHtmlRows += "<td style=\"word-wrap: anywhere;\"><strong>" + domainName + "</strong>";
                        tableHtmlRows += "<div class=\"stat-progress-bar\"><div class=\"stat-progress-fill fill-danger\" style=\"width: " + percentOfMax + "%;\"></div></div>";
                        tableHtmlRows += "</td>";
                        tableHtmlRows += "<td style=\"vertical-align: middle;\"><strong style=\"color: #ea580c;\">" + topBlockedDomains[i].hits.toLocaleString() + "</strong> <span style=\"font-size: 11px; opacity: 0.7;\">(" + percentOfMax + "%)</span></td>";
                        tableHtmlRows += "<td align=\"right\" style=\"vertical-align: middle;\"><div class=\"dropdown\"><a href=\"#\" id=\"btnDashboardTopBlockedDomainsRowOption" + i + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\" style=\"color: inherit; opacity: 0.7;\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"showQueryLogs('" + topBlockedDomains[i].name + "', null, '" + node + "'); return false;\"><i class=\"fa fa-list\"></i> Show Query Logs</a></li>";
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"queryDnsServer('" + topBlockedDomains[i].name + "', null, '" + node + "'); return false;\"><i class=\"fa fa-search\"></i> Query DNS Server</a></li>";
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" data-domain=\"" + htmlEncode(topBlockedDomains[i].name) + "\" onclick=\"allowDomain(this, 'btnDashboardTopBlockedDomainsRowOption'); return false;\"><i class=\"fa fa-check\"></i> Allow Domain</a></li>";
                        tableHtmlRows += "</ul></div></td></tr>";
                    }
                }

                $("#tableTopBlockedDomains").html(tableHtmlRows);
            }

            if (!hideLoader) {
                divDashboardLoader.hide();
                divDashboard.show();
            }
            isPollingDashboard = false;
        },
        error: function () {
            isPollingDashboard = false;
        },
        invalidToken: function () {
            isPollingDashboard = false;
            showPageLogin();
        },
        objLoaderPlaceholder: divDashboardLoader,
        dontHideAlert: hideLoader
    });
}

function showTopStats(statsType, limit) {
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

    var node = $("#optDashboardClusterNode").val();

    HTTPRequest({
        url: "api/dashboard/stats/getTop?type=" + type + custom + "&statsType=" + statsType + "&limit=" + limit + "&node=" + encodeURIComponent(node),
        token: sessionData.token,
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
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"showQueryLogs(null, '" + topClients[i].name + "', '" + node + "'); return false;\">Show Query Logs</a></li>";
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
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"showQueryLogs('" + topDomains[i].name + "', null, '" + node + "'); return false;\">Show Query Logs</a></li>";
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
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"showQueryLogs('" + topBlockedDomains[i].name + "', null, '" + node + "'); return false;\">Show Query Logs</a></li>";
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

function backupSettings(objBtn) {
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

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/user/createSingleUseToken",
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");

            window.open("api/settings/backup?token=" + responseJSON.response.token + "&authConfig=" + authConfig + "&clusterConfig=" + clusterConfig + "&webServiceSettings=" + webServiceSettings + "&dnsSettings=" + dnsSettings + "&logSettings=" + logSettings + "&zones=" + zones + "&allowedZones=" + allowedZones + "&blockedZones=" + blockedZones + "&blockLists=" + blockLists + "&apps=" + apps + "&scopes=" + scopes + "&stats=" + stats + "&logs=" + logs + "&node=" + encodeURIComponent(node) + "&ts=" + (new Date().getTime()), "_blank");

            $("#modalBackupSettings").modal("hide");
            showAlert("success", "Backed Up!", "Settings were backed up successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        },
        objAlertPlaceholder: divBackupSettingsAlert
    });
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
        url: "api/settings/restore?authConfig=" + authConfig + "&clusterConfig=" + clusterConfig + "&webServiceSettings=" + webServiceSettings + "&dnsSettings=" + dnsSettings + "&logSettings=" + logSettings + "&zones=" + zones + "&allowedZones=" + allowedZones + "&blockedZones=" + blockedZones + "&blockLists=" + blockLists + "&apps=" + apps + "&scopes=" + scopes + "&stats=" + stats + "&logs=" + logs + "&deleteExistingFiles=" + deleteExistingFiles + "&node=" + encodeURIComponent(node),
        token: sessionData.token,
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

function updateQuickThemeIcon() {
    var icon = $("#iconQuickTheme");
    var label = $("#lblQuickThemeText");
    var iconLegacy = $("#iconQuickThemeLegacy");
    var labelLegacy = $("#lblQuickThemeTextLegacy");
    var loginPill = $("#lblLoginThemePill");

    var themeName = "Dark Blue";
    var iconClass = "fa fa-moon-o";
    var nextTheme = "Dark Grey";

    if (document.body.classList.contains("dark-mode")) {
        themeName = "Dark Blue";
        iconClass = "fa fa-moon-o";
        nextTheme = "Dark Grey";
    } else if (document.body.classList.contains("dark-grey-mode")) {
        themeName = "Dark Grey";
        iconClass = "fa fa-circle";
        nextTheme = "Light";
    } else if (document.body.classList.contains("amber-mode")) {
        themeName = "Amber";
        iconClass = "fa fa-fire";
        nextTheme = "Dark Blue";
    } else {
        themeName = "Light";
        iconClass = "fa fa-sun-o";
        nextTheme = "Dark Blue";
    }

    if (icon.length) icon.attr("class", iconClass);
    if (label.length) label.text(themeName);
    if (iconLegacy.length) iconLegacy.attr("class", iconClass);
    if (labelLegacy.length) labelLegacy.text(themeName);
    if (loginPill.length) loginPill.text(themeName);

    $("#btnQuickThemeToggle").attr("title", "Theme: " + themeName + ". Click to cycle to " + nextTheme);
    $("#btnQuickThemeToggleLegacy").attr("title", "Theme: " + themeName + ". Click to cycle to " + nextTheme);
}

function toggleQuickTheme() {
    if (document.body.classList.contains("dark-mode")) {
        changeTheme("dark-grey");
    } else if (document.body.classList.contains("dark-grey-mode")) {
        changeTheme("light");
    } else {
        changeTheme("dark");
    }
}

function initTheme() {
    $("#btnQuickThemeToggle").show();

    if (window.matchMedia) {
        window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", e => {
            const currentTheme = localStorage.getItem("theme_preference") || localStorage.getItem("theme");
            switch (currentTheme) {
                case "light":
                case "dark":
                case "dark-grey":
                case "amber":
                    // user chose explicit preference, do not override
                    break;

                default:
                    if (e.matches)
                        applyDarkMode();
                    else
                        applyLightMode();

                    break;
            }
        });
    }

    const currentTheme = localStorage.getItem("theme_preference") || localStorage.getItem("theme");
    changeTheme(currentTheme);
}

function changeTheme(newTheme) {
    switch (newTheme) {
        case "light":
            applyLightMode();
            break;

        case "dark":
            applyDarkMode();
            break;

        case "dark-grey":
            applyDarkGreyMode();
            break;

        case "amber":
            applyAmberMode();
            break;

        default:
            newTheme = "system";
            if (window.matchMedia) {
                if (window.matchMedia("(prefers-color-scheme: dark)").matches)
                    applyDarkMode();
                else
                    applyLightMode();
            } else {
                applyLightMode();
            }

            break;
    }

    localStorage.setItem("theme", newTheme);
    localStorage.setItem("theme_preference", newTheme);
    updateQuickThemeIcon();

    if (window.chartDashboardMain) {
        [window.chartDashboardMain, window.chartDashboardCache, window.chartDashboardClients, window.chartDashboardBlocked, window.chartDashboardHealth, window.chartDashboardPie, window.chartDashboardPie2, window.chartDashboardPie3].forEach(function (c) {
            if (c) {
                updateChartTheme(c);
                c.update();
            }
        });
    }
}

function applyDarkMode() {
    document.body.classList.add("dark-mode");
    document.body.classList.remove("light-mode", "dark-grey-mode", "amber-mode");
    updateQuickThemeIcon();
}

function applyDarkGreyMode() {
    document.body.classList.add("dark-grey-mode");
    document.body.classList.remove("light-mode", "dark-mode", "amber-mode");
    updateQuickThemeIcon();
}

function applyLightMode() {
    document.body.classList.add("light-mode");
    document.body.classList.remove("dark-mode", "dark-grey-mode", "amber-mode");
    updateQuickThemeIcon();
}

function applyAmberMode() {
    document.body.classList.add("amber-mode");
    document.body.classList.remove("light-mode", "dark-mode", "dark-grey-mode");
    updateQuickThemeIcon();
}

function showChangeThemeModal() {
    const currentTheme = localStorage.getItem("theme_preference") || localStorage.getItem("theme");
    switch (currentTheme) {
        case "light":
            $("#rdChangeThemeLight").prop("checked", true);
            break;

        case "dark":
            $("#rdChangeThemeDark").prop("checked", true);
            break;

        case "dark-grey":
            $("#rdChangeThemeDarkGrey").prop("checked", true);
            break;

        case "amber":
            $("#rdChangeThemeAmber").prop("checked", true);
            break;

        default:
            $("#rdChangeThemeSystem").prop("checked", true);
            break;
    }

    const currentLayout = localStorage.getItem("technitium_layout") || "modern";
    if (currentLayout === "classic") {
        $("#rdChangeLayoutClassic").prop("checked", true);
    } else {
        $("#rdChangeLayoutModern").prop("checked", true);
    }

    $("#modalChangeTheme").modal("show");
}

// --- Modern Sidebar & App Shell Navigation System ---
const APP_TAB_METADATA = {
    "Dashboard": {
        title: "Dashboard",
        desc: "Real-time overview of your DNS server telemetry & performance",
        legacyTab: "Dashboard",
        refresh: function () { if (typeof refreshDashboard === "function") refreshDashboard(); }
    },
    "Zones": {
        title: "DNS Zones",
        desc: "Manage authoritative primary, secondary, stub, and forwarder zones",
        legacyTab: "Zones",
        refresh: function () { if (typeof refreshZones === "function") refreshZones(true); }
    },
    "CachedZones": {
        title: "DNS Cache",
        desc: "Inspect, view, and flush cached domain records and query cache",
        legacyTab: "CachedZones",
        refresh: function () { }
    },
    "AllowedZones": {
        title: "Allowed Domains",
        desc: "Allowlisted domain names and whitelist routing policies",
        legacyTab: "AllowedZones",
        refresh: function () { }
    },
    "BlockedZones": {
        title: "Blocked Domains",
        desc: "Blocklisted domain names and custom DNS filter policies",
        legacyTab: "BlockedZones",
        refresh: function () { }
    },
    "Apps": {
        title: "DNS Apps & Plugins",
        desc: "Manage and configure DNS server applications and extensions",
        legacyTab: "Apps",
        refresh: function () { if (typeof refreshApps === "function") refreshApps(); }
    },
    "DnsClient": {
        title: "DNS Client & Query Tool",
        desc: "Interactive DNS resolver tool for query diagnostics and testing",
        legacyTab: "DnsClient",
        refresh: function () { }
    },
    "Settings": {
        title: "DNS Server Settings",
        desc: "Configure network, forwarders, recursion, blocking, and web service",
        legacyTab: "Settings",
        refresh: function () { if (typeof refreshDnsSettings === "function") refreshDnsSettings(); }
    },
    "DhcpServer": {
        title: "DHCP Server",
        desc: "Manage IP allocation scopes, active client leases, and reserved addresses",
        legacyTab: "Dhcp",
        refresh: function () { if (typeof refreshDhcpTab === "function") refreshDhcpTab(); }
    },
    "Administration": {
        title: "Server Administration",
        desc: "User management, cluster synchronization, permissions, and active sessions",
        legacyTab: "Admin",
        refresh: function () { if (typeof refreshAdminTab === "function") refreshAdminTab(); }
    },
    "Logs": {
        title: "Server Logs & Audit",
        desc: "Real-time log viewer and query logging history analytics",
        legacyTab: "Logs",
        refresh: function () { if (typeof refreshLogsTab === "function") refreshLogsTab(); }
    },
    "About": {
        title: "About Technitium DNS",
        desc: "Server version, system environment, uptime, and licensing information",
        legacyTab: "About",
        refresh: function () { }
    }
};

// Compatibility aliases for sidebar tab switching
APP_TAB_METADATA["Dhcp"] = APP_TAB_METADATA["DhcpServer"];
APP_TAB_METADATA["Admin"] = APP_TAB_METADATA["Administration"];
APP_TAB_METADATA["Cache"] = APP_TAB_METADATA["CachedZones"];
APP_TAB_METADATA["Allowed"] = APP_TAB_METADATA["AllowedZones"];
APP_TAB_METADATA["Blocked"] = APP_TAB_METADATA["BlockedZones"];

function switchAppTab(tabName) {
    const meta = APP_TAB_METADATA[tabName];
    if (!meta) return;

    // 1. Activate sidebar nav item
    $(".sidebar-nav-item").removeClass("active");
    $("#sidebarNavItem" + tabName).addClass("active");

    // 2. Trigger corresponding legacy tab click
    $("#mainPanelTabList" + meta.legacyTab + " a").tab("show");
    if (meta.refresh) {
        meta.refresh();
    }

    if (tabName === "Dashboard") {
        isDashboardTabActive = true;
        startAutoRefreshTimer();
    } else {
        isDashboardTabActive = false;
        stopAutoRefreshTimer();
    }

    // 3. Update topbar breadcrumbs and page titles
    updateAppBreadcrumbs(tabName);

    // 4. Auto-collapse on small screens
    if ($(window).width() <= 768) {
        $("#appSidebar").removeClass("expanded");
    }
}

function updateAppBreadcrumbs(tabName) {
    const meta = APP_TAB_METADATA[tabName];
    if (!meta) return;

    $("#lblBreadcrumbSection").text(meta.title);
    $("#lblAppPageTitle").text(meta.title);
    $("#lblAppPageDesc").text(meta.desc);
}

function toggleSidebar() {
    var sidebar = $("#appSidebar");
    if ($(window).width() <= 768) {
        sidebar.toggleClass("expanded");
    } else {
        sidebar.toggleClass("collapsed");
        var isCollapsed = sidebar.hasClass("collapsed");
        localStorage.setItem("sidebar_collapsed", isCollapsed);
        $("#iconSidebarCollapse").attr("class", isCollapsed ? "fa fa-chevron-right" : "fa fa-chevron-left");
    }
}

function refreshCurrentAppTab() {
    var icon = $("#iconTopbarRefresh");
    icon.addClass("fa-spin");
    setTimeout(function () { icon.removeClass("fa-spin"); }, 1000);

    var activeSidebar = $(".sidebar-nav-item.active");
    if (activeSidebar.length > 0) {
        var id = activeSidebar.attr("id");
        if (id) {
            var tabName = id.replace("sidebarNavItem", "");
            var meta = APP_TAB_METADATA[tabName];
            if (meta && meta.refresh) {
                meta.refresh();
                return;
            }
        }
    }
    if (typeof refreshDashboard === "function") {
        refreshDashboard();
    }
}

// --- Layout Switcher System (Modern vs Classic) ---
function initLayout() {
    const savedLayout = localStorage.getItem("technitium_layout") || "modern";
    applyLayout(savedLayout);
}

function setLayout(layout) {
    localStorage.setItem("technitium_layout", layout);
    applyLayout(layout);
}

function toggleLayout() {
    const isClassic = document.body.classList.contains("layout-classic");
    const nextLayout = isClassic ? "modern" : "classic";
    setLayout(nextLayout);
}

function applyLayout(layout) {
    if (layout === "classic") {
        document.body.classList.add("layout-classic");
        document.body.classList.remove("layout-modern");
        $("#rdChangeLayoutClassic").prop("checked", true);
        $("#lblQuickLayoutText").text("Classic");
        $("#lblQuickLayoutTextLegacy").text("Classic");
        $("#lblLoginLayoutPill").text("Classic");
        $("#lblMnuLayoutText").text("Modern");
        $("#lblMnuLayoutTextSidebar").text("Modern");
        $("#lblMnuLayoutTextTopbar").text("Modern");
        $("#btnQuickLayoutToggle").attr("title", "Layout: Classic. Click to switch to Modern");
        $("#btnQuickLayoutToggleLegacy").attr("title", "Layout: Classic. Click to switch to Modern");

        $("#header").show();
        $("#appSidebar").hide();
        $("#appTopBar").hide();
        $("#appShell").show();
        if (!$("#pageLogin").is(":visible")) {
            $("#pageMain").show();
        }
    } else {
        // Modern layout is default
        document.body.classList.add("layout-modern");
        document.body.classList.remove("layout-classic");
        $("#rdChangeLayoutModern").prop("checked", true);
        $("#lblQuickLayoutText").text("Modern");
        $("#lblQuickLayoutTextLegacy").text("Modern");
        $("#lblLoginLayoutPill").text("Modern");
        $("#lblMnuLayoutText").text("Classic");
        $("#lblMnuLayoutTextSidebar").text("Classic");
        $("#lblMnuLayoutTextTopbar").text("Classic");
        $("#btnQuickLayoutToggle").attr("title", "Layout: Modern (Default). Click to switch to Classic");
        $("#btnQuickLayoutToggleLegacy").attr("title", "Layout: Modern (Default). Click to switch to Classic");

        $("#header").hide();
        $("#appShell").css("display", "flex").show();
        $("#appSidebar").show();
        $("#appTopBar").show();
        if (!$("#pageLogin").is(":visible")) {
            $("#pageMain").show();
        }
    }

    // Sync active tab between sidebar navigation and classic horizontal tabs
    var activeSidebar = $(".sidebar-nav-item.active");
    if (activeSidebar.length) {
        var id = activeSidebar.attr("id");
        if (id) {
            var tabName = id.replace("sidebarNavItem", "");
            var meta = APP_TAB_METADATA[tabName];
            if (meta) {
                $("#mainPanelTabList" + meta.legacyTab + " a").tab("show");
            }
        }
    }
}

// --- Dashboard Chart Sub-View Switcher & Auto-Refresh System ---
function renderOrUpdateSubViewChart(viewName) {
    if (!viewName) viewName = localStorage.getItem("dashboard_chart_subview") || "traffic";
    if (!window.lastDashboardResponse) return;

    var resp = window.lastDashboardResponse;
    var isDark = document.body.classList.contains("dark-mode") || document.body.classList.contains("dark-grey-mode");

    if (viewName === "traffic") {
        if (window.chartDashboardMain) {
            window.chartDashboardMain.resize();
            window.chartDashboardMain.update(0);
        }
    } else if (viewName === "cache") {
        var canvas = document.getElementById("canvasDashboardCache");
        if (!canvas) return;

        var cacheDatasets = [];
        if (resp.mainChartData && resp.mainChartData.datasets) {
            resp.mainChartData.datasets.forEach(function (ds) {
                var label = ds.label ? ds.label.toLowerCase() : "";
                if (label.indexOf("cache") !== -1 || label.indexOf("recurs") !== -1 || label.indexOf("author") !== -1 || label.indexOf("block") !== -1) {
                    var copy = $.extend(true, {}, ds);
                    if (label.indexOf("cache") !== -1) {
                        copy.borderColor = "#10b981";
                        copy.backgroundColor = "rgba(16, 185, 129, 0.15)";
                    } else if (label.indexOf("recurs") !== -1) {
                        copy.borderColor = "#3b82f6";
                        copy.backgroundColor = "rgba(59, 130, 246, 0.15)";
                    } else if (label.indexOf("author") !== -1) {
                        copy.borderColor = "#8b5cf6";
                        copy.backgroundColor = "rgba(139, 92, 246, 0.15)";
                    } else if (label.indexOf("block") !== -1) {
                        copy.borderColor = "#f97316";
                        copy.backgroundColor = "rgba(249, 115, 22, 0.15)";
                    }
                    cacheDatasets.push(copy);
                }
            });
        }

        var cacheChartData = {
            labels: resp.mainChartData ? resp.mainChartData.labels : [],
            datasets: cacheDatasets
        };

        if (window.chartDashboardCache == null) {
            var ctx = canvas.getContext('2d');
            window.chartDashboardCache = new Chart(ctx, {
                type: 'line',
                data: cacheChartData,
                options: createDashboardChartOptions()
            });
        } else {
            window.chartDashboardCache.data = cacheChartData;
            updateChartTheme(window.chartDashboardCache);
            window.chartDashboardCache.resize();
            window.chartDashboardCache.update(0);
        }
    } else if (viewName === "clients") {
        var canvas = document.getElementById("canvasDashboardClients");
        if (!canvas) return;

        var topClients = resp.topClients ? resp.topClients.slice(0, 10) : [];
        var clientLabels = topClients.map(function (c) { return c.name || "Unknown"; });
        var clientHits = topClients.map(function (c) { return c.hits || 0; });

        var clientsChartData = {
            labels: clientLabels,
            datasets: [{
                label: "Client Queries",
                data: clientHits,
                backgroundColor: "rgba(59, 130, 246, 0.85)",
                borderColor: "#3b82f6",
                borderWidth: 1.5,
                hoverBackgroundColor: "#2563eb"
            }]
        };

        if (window.chartDashboardClients == null) {
            var ctx = canvas.getContext('2d');
            window.chartDashboardClients = new Chart(ctx, {
                type: 'horizontalBar',
                data: clientsChartData,
                options: createHorizontalBarChartOptions("Client Queries")
            });
        } else {
            window.chartDashboardClients.data = clientsChartData;
            updateChartTheme(window.chartDashboardClients);
            window.chartDashboardClients.resize();
            window.chartDashboardClients.update(0);
        }
    } else if (viewName === "blocked") {
        var canvas = document.getElementById("canvasDashboardBlocked");
        if (!canvas) return;

        var topBlocked = resp.topBlockedDomains ? resp.topBlockedDomains.slice(0, 10) : [];
        var blockedLabels = topBlocked.map(function (b) { return b.name || "Unknown"; });
        var blockedHits = topBlocked.map(function (b) { return b.hits || 0; });

        var blockedChartData = {
            labels: blockedLabels,
            datasets: [{
                label: "Blocked Requests",
                data: blockedHits,
                backgroundColor: "rgba(249, 115, 22, 0.85)",
                borderColor: "#f97316",
                borderWidth: 1.5,
                hoverBackgroundColor: "#ea580c"
            }]
        };

        if (window.chartDashboardBlocked == null) {
            var ctx = canvas.getContext('2d');
            window.chartDashboardBlocked = new Chart(ctx, {
                type: 'horizontalBar',
                data: blockedChartData,
                options: createHorizontalBarChartOptions("Blocked Requests")
            });
        } else {
            window.chartDashboardBlocked.data = blockedChartData;
            updateChartTheme(window.chartDashboardBlocked);
            window.chartDashboardBlocked.resize();
            window.chartDashboardBlocked.update(0);
        }
    } else if (viewName === "health") {
        var canvas = document.getElementById("canvasDashboardHealth");
        if (!canvas) return;

        var healthDatasets = [];
        if (resp.mainChartData && resp.mainChartData.datasets) {
            resp.mainChartData.datasets.forEach(function (ds) {
                var label = ds.label ? ds.label.toLowerCase() : "";
                if (label.indexOf("fail") !== -1 || label.indexOf("nx") !== -1 || label.indexOf("refus") !== -1 || label.indexOf("drop") !== -1) {
                    var copy = $.extend(true, {}, ds);
                    if (label.indexOf("fail") !== -1) {
                        copy.borderColor = "#ef4444";
                        copy.backgroundColor = "rgba(239, 68, 68, 0.15)";
                    } else if (label.indexOf("nx") !== -1) {
                        copy.borderColor = "#f59e0b";
                        copy.backgroundColor = "rgba(245, 158, 11, 0.15)";
                    } else if (label.indexOf("refus") !== -1) {
                        copy.borderColor = "#06b6d4";
                        copy.backgroundColor = "rgba(6, 182, 212, 0.15)";
                    } else if (label.indexOf("drop") !== -1) {
                        copy.borderColor = "#64748b";
                        copy.backgroundColor = "rgba(100, 116, 139, 0.15)";
                    }
                    healthDatasets.push(copy);
                }
            });
        }

        var healthChartData = {
            labels: resp.mainChartData ? resp.mainChartData.labels : [],
            datasets: healthDatasets
        };

        if (window.chartDashboardHealth == null) {
            var ctx = canvas.getContext('2d');
            window.chartDashboardHealth = new Chart(ctx, {
                type: 'line',
                data: healthChartData,
                options: createDashboardChartOptions()
            });
        } else {
            window.chartDashboardHealth.data = healthChartData;
            updateChartTheme(window.chartDashboardHealth);
            window.chartDashboardHealth.resize();
            window.chartDashboardHealth.update(0);
        }
    }
}

function switchDashboardChartView(viewName) {
    if (!viewName) viewName = "traffic";
    var cap = viewName.charAt(0).toUpperCase() + viewName.slice(1);

    $(".btn-chart-subview").removeClass("active");
    $("#btnSubView" + cap).addClass("active");

    var titleHtml = '<i class="fa fa-area-chart"></i> DNS Query & Block Traffic Activity';

    if (viewName === "traffic") {
        $("#lblDashboardChartTitle").html(titleHtml);
        if (window.activeDashboardFilter) {
            applyActiveDashboardFilter();
        } else {
            renderMainChartLegend();
        }
    } else {
        var legendHtml = "";
        if (viewName === "cache") {
            titleHtml = '<i class="fa fa-bolt" style="color: #10b981;"></i> Cache Efficiency & Resolution Activity';
            legendHtml = '<span class="legend-dot" style="background:#10b981;"></span> Cached <span class="legend-dot" style="background:#3b82f6; margin-left: 14px;"></span> Recursive <span class="legend-dot" style="background:#8b5cf6; margin-left: 14px;"></span> Authoritative <span class="legend-dot" style="background:#f97316; margin-left: 14px;"></span> Blocked';
        } else if (viewName === "clients") {
            titleHtml = '<i class="fa fa-users" style="color: #3b82f6;"></i> Top Active DNS Clients';
            legendHtml = '<span class="legend-dot" style="background:#3b82f6;"></span> Query Volume by Client IP / Host';
        } else if (viewName === "blocked") {
            titleHtml = '<i class="fa fa-shield" style="color: #f97316;"></i> Top Blocked Domains & Ad Trackers';
            legendHtml = '<span class="legend-dot" style="background:#f97316;"></span> Intercepted Requests';
        } else if (viewName === "health") {
            titleHtml = '<i class="fa fa-heartbeat" style="color: #ef4444;"></i> Resolver Health & Query Errors';
            legendHtml = '<span class="legend-dot" style="background:#ef4444;"></span> Server Failure <span class="legend-dot" style="background:#f59e0b; margin-left: 14px;"></span> NX Domain <span class="legend-dot" style="background:#06b6d4; margin-left: 14px;"></span> Refused <span class="legend-dot" style="background:#64748b; margin-left: 14px;"></span> Dropped';
        }
        $("#lblDashboardChartTitle").html(titleHtml);
        $("#lblDashboardChartLegend").html(legendHtml);
    }

    $(".chart-view-wrap").hide().removeClass("active");
    $("#chartWrap" + cap).show().addClass("active");

    localStorage.setItem("dashboard_chart_subview", viewName);

    renderOrUpdateSubViewChart(viewName);
}

function setAutoRefreshInterval(cadence) {
    if (typeof cadence === "string") {
        if (cadence === "3s" || cadence === "3000") cadence = 3000;
        else if (cadence === "10s" || cadence === "10000") cadence = 10000;
        else if (cadence === "off" || cadence === "0" || cadence === "manual") cadence = 0;
        else cadence = 10000;
    } else if (typeof cadence === "number") {
        if (cadence !== 3000 && cadence !== 10000 && cadence !== 0) cadence = 10000;
    } else {
        cadence = 10000;
    }

    autoRefreshInterval = cadence;
    localStorage.setItem("dashboard_auto_refresh_cadence", cadence);

    var statusText = "Normal (10s)";
    var beaconClass = "live-pulse-beacon";

    $("#itemAutoRefresh3s, #itemAutoRefresh3sLegacy").removeClass("active");
    $("#itemAutoRefresh10s, #itemAutoRefresh10sLegacy").removeClass("active");
    $("#itemAutoRefreshOff, #itemAutoRefreshOffLegacy").removeClass("active");

    if (cadence === 3000) {
        statusText = "Live (3s)";
        beaconClass = "live-pulse-beacon fast";
        $("#itemAutoRefresh3s, #itemAutoRefresh3sLegacy").addClass("active");
    } else if (cadence === 10000) {
        statusText = "Normal (10s)";
        beaconClass = "live-pulse-beacon";
        $("#itemAutoRefresh10s, #itemAutoRefresh10sLegacy").addClass("active");
    } else {
        statusText = "Manual (Off)";
        beaconClass = "live-pulse-beacon paused";
        $("#itemAutoRefreshOff, #itemAutoRefreshOffLegacy").addClass("active");
    }

    $("#lblAutoRefreshStatus, #lblAutoRefreshStatusLegacy").text(statusText);
    $("#livePulseBeacon, #livePulseBeaconLegacy").attr("class", beaconClass);

    restartAutoRefreshTimer();
}

function startAutoRefreshTimer() {
    stopAutoRefreshTimer();
    if (autoRefreshInterval <= 0) return;
    if (!isDashboardTabActive || document.hidden) return;

    autoRefreshTimer = setInterval(function () {
        onAutoRefreshTick();
    }, autoRefreshInterval);
}

function stopAutoRefreshTimer() {
    if (autoRefreshTimer !== null) {
        clearInterval(autoRefreshTimer);
        autoRefreshTimer = null;
    }
}

function restartAutoRefreshTimer() {
    stopAutoRefreshTimer();
    startAutoRefreshTimer();
}

function onAutoRefreshTick() {
    if (isPollingDashboard) return;
    if (!isDashboardTabActive || document.hidden) {
        stopAutoRefreshTimer();
        return;
    }

    // Flash beacon subtly to indicate active data sync
    var beacons = $("#livePulseBeacon, #livePulseBeaconLegacy");
    beacons.addClass("flash");
    setTimeout(function () { beacons.removeClass("flash"); }, 400);

    if (typeof refreshDashboard === "function") {
        isPollingDashboard = true;
        refreshDashboard(true);
    }
}

function createDashboardChartOptions() {
    var isDark = document.body.classList.contains("dark-mode") || document.body.classList.contains("dark-grey-mode");
    return {
        elements: {
            line: {
                tension: 0.35
            }
        },
        scales: {
            yAxes: [{
                ticks: {
                    beginAtZero: true,
                    fontColor: isDark ? "#94a3b8" : "#64748b"
                },
                gridLines: {
                    color: isDark ? "rgba(255, 255, 255, 0.06)" : "rgba(0, 0, 0, 0.06)"
                }
            }],
            xAxes: [{
                ticks: {
                    fontColor: isDark ? "#94a3b8" : "#64748b"
                },
                gridLines: {
                    color: isDark ? "rgba(255, 255, 255, 0.04)" : "rgba(0, 0, 0, 0.04)"
                }
            }]
        },
        legend: {
            onClick: chartLegendOnClick
        }
    };
}

function createHorizontalBarChartOptions(datasetLabel) {
    var isDark = document.body.classList.contains("dark-mode") || document.body.classList.contains("dark-grey-mode");
    return {
        responsive: true,
        legend: {
            display: false
        },
        scales: {
            xAxes: [{
                ticks: {
                    beginAtZero: true,
                    callback: function (val) {
                        return Number(val).toLocaleString();
                    },
                    fontColor: isDark ? "#94a3b8" : "#64748b"
                },
                gridLines: {
                    color: isDark ? "rgba(255, 255, 255, 0.06)" : "rgba(0, 0, 0, 0.06)"
                }
            }],
            yAxes: [{
                ticks: {
                    fontColor: isDark ? "#cbd5e1" : "#334155"
                },
                gridLines: {
                    display: false
                }
            }]
        },
        tooltips: {
            callbacks: {
                label: function (tooltipItem, data) {
                    return " " + (datasetLabel || "Queries") + ": " + Number(tooltipItem.xLabel).toLocaleString();
                }
            }
        }
    };
}

function updateChartTheme(chart) {
    if (!chart || !chart.options || !chart.options.scales) return;
    var isDark = document.body.classList.contains("dark-mode") || document.body.classList.contains("dark-grey-mode");
    var gridColor = isDark ? "rgba(255, 255, 255, 0.06)" : "rgba(0, 0, 0, 0.06)";
    var tickColor = isDark ? "#94a3b8" : "#64748b";

    if (chart.options.scales.xAxes) {
        chart.options.scales.xAxes.forEach(function (axis) {
            if (axis.gridLines) axis.gridLines.color = isDark ? "rgba(255, 255, 255, 0.04)" : "rgba(0, 0, 0, 0.04)";
            if (axis.ticks) axis.ticks.fontColor = tickColor;
        });
    }
    if (chart.options.scales.yAxes) {
        chart.options.scales.yAxes.forEach(function (axis) {
            if (axis.gridLines && axis.gridLines.display !== false) axis.gridLines.color = gridColor;
            if (axis.ticks) axis.ticks.fontColor = isDark ? "#cbd5e1" : "#334155";
        });
    }
}
