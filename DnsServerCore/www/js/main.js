
var token = null;
var refreshZonesTimerHandle;

function showPageLogin() {
    hideAlert();

    $("#pageMain").hide();
    $("#mnuUser").hide();

    $("#txtUser").val("");
    $("#txtPass").val("");
    $("#btnLogin").button('reset');
    $("#pageLogin").show();

    $("#txtUser").focus();

    if (refreshZonesTimerHandle != null) {
        clearInterval(refreshZonesTimerHandle);
        refreshZonesTimerHandle = null;
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
    $("#mainPanelTabListZones").addClass("active");
    $("#mainPanelTabPaneZones").addClass("active");

    $("#divZoneViewer").hide();

    $("#txtDnsClientNameServer").val("This Server (this-server)");
    $("#txtDnsClientDomain").val("");
    $("#optDnsClientType").val("A");
    $("#optDnsClientProtocol").val("UDP");
    $("#divDnsClientLoader").hide();
    $("#divDnsClientOutput").text("");
    $("#preDnsClientOutput").hide();

    $("#divLogViewer").hide();

    $("#pageMain").show();

    loadDnsSettings();
    refreshZonesList();
    refreshCachedZonesList();
    checkForUpdate();

    refreshZonesTimerHandle = setInterval(function () { refreshZonesList(true); }, 60000);
}

$(function () {
    var headerHtml = $("#header").html();

    $("#header").html("<div class=\"title\"><a href=\"/\"><img src=\"/img/logo25x25.png\" alt=\"Technitium Logo\" /><span class=\"text\" style=\"color: #ffffff;\">Technitium</span></a>" + headerHtml + "</div>");
    $("#footer").html("<div class=\"content\"><a href=\"https://technitium.com/\" target=\"_blank\">Technitium</a> | <a href=\"https://blog.technitium.com/\" target=\"_blank\">Blog</a> | <a href=\"https://dnsclient.net/\" target=\"_blank\">DNS Client</a> | <a href=\"https://github.com/TechnitiumSoftware/DnsServer\" target=\"_blank\"><i class=\"fa fa-github\"></i>&nbsp;GitHub</a> | <a href=\"https://technitium.com/aboutus.html\" target=\"_blank\">About</a></div>");

    //dropdown list box support
    $('.dropdown').on('click', 'a', function (e) {
        e.preventDefault();

        var itemText = $(this).text();
        $(this).closest('.dropdown').find('input').val(itemText);

        if (itemText.indexOf("TLS") !== -1)
            $("#optDnsClientProtocol").val("TLS");
        else if (itemText.indexOf("HTTPS-JSON") !== -1)
            $("#optDnsClientProtocol").val("HttpsJson");
        else if (itemText.indexOf("HTTPS") !== -1)
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

    $("#divNetworkProxy input").click(function () {
        var proxyType = $('input[name=rdProxyType]:checked').val().toLowerCase();
        if (proxyType === "none") {
            $("#txtProxyAddress").prop("disabled", true);
            $("#txtProxyPort").prop("disabled", true);
            $("#txtProxyUsername").prop("disabled", true);
            $("#txtProxyPassword").prop("disabled", true);
        }
        else {
            $("#txtProxyAddress").prop("disabled", false);
            $("#txtProxyPort").prop("disabled", false);
            $("#txtProxyUsername").prop("disabled", false);
            $("#txtProxyPassword").prop("disabled", false);
        }
    });

    $("#chkAllowRecursion").click(function () {
        var allowRecursion = $("#chkAllowRecursion").prop('checked');
        $("#chkAllowRecursionOnlyForPrivateNetworks").prop('disabled', !allowRecursion);
    });

    showPageLogin();
    login("admin", "admin");
});

function login(username, password) {

    var autoLogin = false;

    if (username == null) {
        username = $("#txtUser").val();
        password = $("#txtPass").val();
    }
    else {
        autoLogin = true;
    }

    if ((username === null) || (username === "")) {
        showAlert("warning", "Missing!", "Please enter username.");
        return false;
    }

    if ((password === null) || (password === "")) {
        showAlert("warning", "Missing!", "Please enter password.");
        return false;
    }

    var btn = $("#btnLogin").button('loading');

    HTTPRequest({
        url: "/api/login?user=" + username + "&pass=" + password,
        success: function (responseJSON) {
            token = responseJSON.token;

            showPageMain(username);

            if ((username === "admin") && (password === "admin")) {
                $('#modalChangePassword').modal();
            }
        },
        error: function () {
            btn.button('reset');

            if (autoLogin)
                hideAlert();
        }
    });

    return false;
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

    return false;
}

function resetChangePasswordModal() {

    $("#divChangePasswordAlert").html("");
    $("#txtChangePasswordNewPassword").val("");
    $("#txtChangePasswordConfirmPassword").val("");

    return false;
}

function changePassword() {

    var divChangePasswordAlert = $("#divChangePasswordAlert");
    var newPassword = $("#txtChangePasswordNewPassword").val();
    var confirmPassword = $("#txtChangePasswordConfirmPassword").val();

    if ((newPassword === null) || (newPassword === "")) {
        showAlert("warning", "Missing!", "Please enter new password.", divChangePasswordAlert);
        return false;
    }

    if ((confirmPassword === null) || (confirmPassword === "")) {
        showAlert("warning", "Missing!", "Please enter confirm password.", divChangePasswordAlert);
        return false;
    }

    if (newPassword !== confirmPassword) {
        showAlert("warning", "Mismatch!", "Passwords do not match. Please try again.", divChangePasswordAlert);
        return false;
    }

    var btn = $("#btnChangePasswordSave").button('loading');

    HTTPRequest({
        url: "/api/changePassword?token=" + token + "&pass=" + newPassword,
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

    return false;
}

function checkForUpdate() {

    HTTPRequest({
        url: "/api/checkForUpdate?token=" + token,
        success: function (responseJSON) {

            var lnkNewVersionAvailable = $("#lnkNewVersionAvailable");

            if (responseJSON.response.updateAvailable) {

                if (responseJSON.response.displayText == null)
                    responseJSON.response.displayText = "New Version Available!";

                lnkNewVersionAvailable.text(responseJSON.response.displayText);
                lnkNewVersionAvailable.attr("href", responseJSON.response.downloadLink);
                lnkNewVersionAvailable.show();
            }
            else {
                lnkNewVersionAvailable.hide();
            }
        },
        invalidToken: function () {
            showPageLogin();
        }
    });

    return false;
}

function loadDnsSettings() {

    var divDnsSettingsLoader = $("#divDnsSettingsLoader");
    var divDnsSettings = $("#divDnsSettings");

    divDnsSettings.hide();
    divDnsSettingsLoader.show();

    HTTPRequest({
        url: "/api/getDnsSettings?token=" + token,
        success: function (responseJSON) {
            document.title = "Technitium DNS Server " + responseJSON.response.version + " - " + responseJSON.response.serverDomain;

            $("#txtServerDomain").val(responseJSON.response.serverDomain);
            $("#lblServerDomain").text(" - " + responseJSON.response.serverDomain);

            $("#txtWebServicePort").val(responseJSON.response.webServicePort);

            $("#chkPreferIPv6").prop("checked", responseJSON.response.preferIPv6);
            $("#chkLogQueries").prop("checked", responseJSON.response.logQueries);
            $("#chkAllowRecursion").prop("checked", responseJSON.response.allowRecursion);
            $("#chkAllowRecursionOnlyForPrivateNetworks").prop('disabled', !responseJSON.response.allowRecursion);
            $("#chkAllowRecursionOnlyForPrivateNetworks").prop("checked", responseJSON.response.allowRecursionOnlyForPrivateNetworks);

            var proxy = responseJSON.response.proxy;
            if (proxy === null) {
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

                $("#txtProxyAddress").prop("disabled", false);
                $("#txtProxyPort").prop("disabled", false);
                $("#txtProxyUsername").prop("disabled", false);
                $("#txtProxyPassword").prop("disabled", false);
            }

            var forwarders = responseJSON.response.forwarders;
            if (forwarders === null) {
                $("#txtForwarders").val("");
            }
            else {
                var value = "";

                for (var i = 0; i < forwarders.length; i++)
                    value += forwarders[i] + "\r\n";

                $("#txtForwarders").val(value);
            }

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
                    $("#rdForwarderProtocolHttpJsons").prop("checked", true);
                    break;

                default:
                    $("#rdForwarderProtocolUdp").prop("checked", true);
                    break;
            }

            divDnsSettingsLoader.hide();
            divDnsSettings.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divDnsSettingsLoader
    });

    return false;
}

function saveDnsSettings() {

    var serverDomain = $("#txtServerDomain").val();

    if ((serverDomain === null) || (serverDomain === "")) {
        showAlert("warning", "Missing!", "Please enter server domain name.");
        return false;
    }

    var webServicePort = $("#txtWebServicePort").val();

    if ((webServicePort === null) || (webServicePort === "")) {
        showAlert("warning", "Missing!", "Please enter web service port.");
        return false;
    }

    var preferIPv6 = $("#chkPreferIPv6").prop('checked');
    var logQueries = $("#chkLogQueries").prop('checked');
    var allowRecursion = $("#chkAllowRecursion").prop('checked');
    var allowRecursionOnlyForPrivateNetworks = $("#chkAllowRecursionOnlyForPrivateNetworks").prop('checked');

    var proxy;
    var proxyType = $('input[name=rdProxyType]:checked').val().toLowerCase();
    if (proxyType === "none") {
        proxy = "&proxyType=" + proxyType;
    }
    else {
        proxy = "&proxyType=" + proxyType + "&proxyAddress=" + $("#txtProxyAddress").val() + "&proxyPort=" + $("#txtProxyPort").val() + "&proxyUsername=" + $("#txtProxyUsername").val() + "&proxyPassword=" + $("#txtProxyPassword").val();
    }

    var forwarders = $("#txtForwarders").val().replace(/\n/g, ",");

    while (forwarders.indexOf(",,") !== -1) {
        forwarders = forwarders.replace(/,,/g, ",");
    }

    if (forwarders.startsWith(","))
        forwarders = forwarders.substr(1);

    if (forwarders.endsWith(","))
        forwarders = forwarders.substr(0, forwarders.length - 1);

    if ((forwarders.length === 0) || (forwarders === ","))
        forwarders = false;
    else
        $("#txtForwarders").val(forwarders.replace(/,/g, "\n"));

    var forwarderProtocol = $('input[name=rdForwarderProtocol]:checked').val();

    var btn = $("#btnSaveDnsSettings").button('loading');

    HTTPRequest({
        url: "/api/setDnsSettings?token=" + token + "&serverDomain=" + serverDomain + "&webServicePort=" + webServicePort + "&preferIPv6=" + preferIPv6 + "&logQueries=" + logQueries + "&allowRecursion=" + allowRecursion + "&allowRecursionOnlyForPrivateNetworks=" + allowRecursionOnlyForPrivateNetworks + proxy + "&forwarders=" + forwarders + "&forwarderProtocol=" + forwarderProtocol,
        success: function (responseJSON) {
            document.title = "Technitium DNS Server " + responseJSON.response.version + " - " + responseJSON.response.serverDomain;
            $("#lblServerDomain").text(" - " + responseJSON.response.serverDomain);
            $("#txtServerDomain").val(responseJSON.response.serverDomain)

            btn.button('reset');
            showAlert("success", "Settings Saved!", "Dns server settings were saved successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
            showPageLogin();
        }
    });

    return false;
}

function flushDnsCache() {

    if (!confirm("Are you sure to flush the DNS server cache?"))
        return false;

    var btn = $("#btnFlushDnsCache").button('loading');

    HTTPRequest({
        url: "/api/flushDnsCache?token=" + token,
        success: function (responseJSON) {
            btn.button('reset');
            showAlert("success", "Cache Flushed!", "Dns server cache was flushed successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
            showPageLogin();
        }
    });

    return false;
}

function deleteCachedZone() {

    var domain = $("#txtCachedZoneViewerTitle").text();

    if (!confirm("Are you sure you want to delete the cached zone '" + domain + "' and all its records?"))
        return false;

    var btn = $("#btnDeleteCachedZone").button('loading');

    HTTPRequest({
        url: "/api/deleteCachedZone?token=" + token + "&domain=" + domain,
        success: function (responseJSON) {
            refreshCachedZonesList(getParentDomain(domain), "up");

            btn.button('reset');
            showAlert("success", "Cached Zone Deleted!", "Cached zone was deleted successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
            showPageLogin();
        }
    });

    return false;
}

function getParentDomain(domain) {

    if ((domain != null) && (domain != "")) {
        var parentDomain;
        var i = domain.indexOf(".");

        if (i == -1)
            parentDomain = "";
        else
            parentDomain = domain.substr(i + 1);

        return parentDomain;
    }

    return null;
}

function refreshCachedZonesList(domain, direction) {

    if (domain == null)
        domain = "";

    domain.toLowerCase();

    var lstCachedZones = $("#lstCachedZones");
    var divCachedZoneViewer = $("#divCachedZoneViewer");
    var preCachedZoneViewerBody = $("#preCachedZoneViewerBody");

    divCachedZoneViewer.hide();
    preCachedZoneViewerBody.hide();

    HTTPRequest({
        url: "/api/listCachedZones?token=" + token + "&domain=" + domain + ((direction == null) ? "" : "&direction=" + direction),
        success: function (responseJSON) {
            var newDomain = responseJSON.response.domain;
            var zones = responseJSON.response.zones;

            var list = "<div class=\"zone\"><a href=\"#\" onclick=\"return refreshCachedZonesList('" + newDomain + "');\"><b>[refresh]</b></a></div>"

            var parentDomain = getParentDomain(newDomain);

            if (parentDomain != null)
                list += "<div class=\"zone\"><a href=\"#\" onclick=\"return refreshCachedZonesList('" + parentDomain + "', 'up');\"><b>[up]</b></a></div>"

            for (var i = 0; i < zones.length; i++) {
                var zoneName = htmlEncode(zones[i]);

                list += "<div class=\"zone\"><a href=\"#\" onclick=\"return refreshCachedZonesList('" + zoneName + "');\">" + zoneName + "</a></div>"
            }

            lstCachedZones.html(list);

            if (newDomain == "") {
                $("#txtCachedZoneViewerTitle").text("<ROOT>");
                $("#btnDeleteCachedZone").hide();
            }
            else {
                $("#txtCachedZoneViewerTitle").text(newDomain);

                if ((newDomain == "root-servers.net") || newDomain.endsWith(".root-servers.net"))
                    $("#btnDeleteCachedZone").hide();
                else
                    $("#btnDeleteCachedZone").show();
            }

            if (responseJSON.response.records.length > 0) {
                preCachedZoneViewerBody.text(JSON.stringify(responseJSON.response.records, null, 2));
                preCachedZoneViewerBody.show();
            }

            divCachedZoneViewer.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        error: function () {
            lstCachedZones.html("<div class=\"zone\"><a href=\"#\" onclick=\"return refreshCachedZonesList('" + domain + "');\"><b>[refresh]</b></a></div>");
        },
        objLoaderPlaceholder: lstCachedZones
    });

    return false;
}

function refreshZonesList(hideLoader) {

    if (hideLoader == null)
        hideLoader = false;

    var lstZones = $("#lstZones");
    var divLoader;

    if (!hideLoader)
        divLoader = lstZones;

    HTTPRequest({
        url: "/api/listZones?token=" + token,
        success: function (responseJSON) {
            var zones = responseJSON.response.zones;

            var list = "";

            for (var i = 0; i < zones.length; i++) {
                var zoneName = htmlEncode(zones[i].zoneName);

                list += "<div class=\"zone\"><a href=\"#\" onclick=\"return viewZone('" + zoneName + "', " + zones[i].disabled + ");\"" + (zones[i].disabled ? "style=\"color: #ffa500 !important\"" : "") + ">" + zoneName + "</a></div>"
            }

            lstZones.html(list);
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divLoader,
        dontHideAlert: hideLoader
    });

    return false;
}

function addZone() {

    var domain = $("#txtAddZone").val();

    if ((domain === null) || (domain === "")) {
        showAlert("warning", "Missing!", "Please enter a domain name to add zone.");
        return false;
    }

    var btn = $("#btnAddZone").button('loading');

    HTTPRequest({
        url: "/api/createZone?token=" + token + "&domain=" + domain,
        success: function (responseJSON) {
            refreshZonesList();
            viewZone(domain, false);

            $("#txtAddZone").val("");
            btn.button('reset');

            showAlert("success", "Zone Added!", "Zone was added successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
            showPageLogin();
        }
    });

    return false;
}

function deleteZone() {

    var domain = $("#spanZoneViewerTitle").text();

    if (!confirm("Are you sure you want to permanently delete the zone '" + domain + "' and all its records?"))
        return false;

    var btn = $("#btnDeleteZone").button('loading');

    HTTPRequest({
        url: "/api/deleteZone?token=" + token + "&domain=" + domain,
        success: function (responseJSON) {
            refreshZonesList();

            $("#divZoneViewer").hide();
            btn.button('reset');

            showAlert("success", "Zone Deleted!", "Zone was deleted successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
            showPageLogin();
        }
    });

    return false;
}

function enableZone() {

    var domain = $("#spanZoneViewerTitle").text();

    if (!confirm("Are you sure you want to enable the zone '" + domain + "'?"))
        return false;

    var btn = $("#btnEnableZone").button('loading');

    HTTPRequest({
        url: "/api/enableZone?token=" + token + "&domain=" + domain,
        success: function (responseJSON) {
            refreshZonesList();

            $("#btnEnableZone").hide();
            $("#btnDisableZone").show();

            btn.button('reset');

            showAlert("success", "Zone Enabled!", "Zone was enabled successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
            showPageLogin();
        }
    });

    return false;
}

function disableZone() {

    var domain = $("#spanZoneViewerTitle").text();

    if (!confirm("Are you sure you want to disable the zone '" + domain + "'?"))
        return false;

    var btn = $("#btnDisableZone").button('loading');

    HTTPRequest({
        url: "/api/disableZone?token=" + token + "&domain=" + domain,
        success: function (responseJSON) {
            refreshZonesList();

            $("#btnEnableZone").show();
            $("#btnDisableZone").hide();

            btn.button('reset');

            showAlert("success", "Zone Disabled!", "Zone was disabled successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
            showPageLogin();
        }
    });

    return false;
}

function viewZone(domain, disabled) {

    var divZoneViewer = $("#divZoneViewer");
    var divZoneViewerBody = $("#divZoneViewerBody");
    var divZoneViewerLoader = $("#divZoneViewerLoader");

    $("#spanZoneViewerTitle").text(domain);

    if (disabled) {
        $("#btnEnableZone").show();
        $("#btnDisableZone").hide();
    }
    else {
        $("#btnEnableZone").hide();
        $("#btnDisableZone").show();
    }

    $("#spanZoneViewerTitleLink").html("<a href=\"http://" + domain + "/\" target=\"_blank\"><span class=\"glyphicon glyphicon-new-window\" aria-hidden=\"true\"></span></a>");

    divZoneViewerLoader.show();
    divZoneViewerBody.hide();
    divZoneViewer.show();

    HTTPRequest({
        url: "/api/getRecords?token=" + token + "&domain=" + domain,
        success: function (responseJSON) {
            var records = responseJSON.response.records;

            var list = "<ul class=\"list-group\">";

            for (var i = 0; i < records.length; i++) {
                list += renderResourceRecord(records[i], domain);
            }

            list += renderAddResourceRecordForm(domain);

            list += "</ul>";

            divZoneViewerBody.html(list);

            divZoneViewerLoader.hide();
            divZoneViewerBody.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divZoneViewerLoader
    });

    return false;
}

function renderResourceRecord(record, domain) {
    switch (record.type) {
        case "SOA":
            return renderSOAResourceRecord(record, domain);

        case "MX":
            return renderMXResourceRecord(record, domain);

        case "SRV":
            return renderSRVResourceRecord(record, domain);

        default:
            return renderStandardResourceRecord(record, domain);
    }
}

function renderStandardResourceRecord(record, domain) {

    var id = Math.floor(Math.random() * 10000);

    var html = "<li id=\"li" + id + "\" class=\"list-group-item resource-record\">";
    html += "<form class=\"form-inline\">";

    //label
    html += "<div class=\"form-group\">";
    html += "<label for=\"optType" + id + "\">Type</label>";
    html += "<select id=\"optType" + id + "\" class=\"form-control\" disabled>";
    html += "<option selected>" + record.type + "</option>";
    html += "</select>";
    html += "</div>";

    //name
    var name = record.name.toLowerCase();

    if (name === domain)
        name = "@";
    else
        name = name.replace("." + domain, "");

    html += "<div class=\"form-group\">";
    html += "<label for=\"txtName" + id + "\">Name</label>";
    html += "<input id=\"txtName" + id + "\" type=\"text\" class=\"form-control\" placeholder=\"@\" style=\"width: 120px;\" value=\"" + name + "\" disabled>";
    html += "</div>";

    //value
    html += "<div class=\"form-group\">";
    html += "<label for=\"txtValue" + id + "\">Value</label>";
    html += "<input id=\"txtValue" + id + "\" type=\"text\" class=\"form-control\" placeholder=\"value\" style=\"width: 250px;\" value=\"" + record.rData.value + "\" disabled>";
    html += "</div>";

    //ttl
    html += "<div class=\"form-group\">";
    html += "<label for=\"txtTtl" + id + "\">TTL</label>";
    html += "<input id=\"txtTtl" + id + "\" type=\"number\" class=\"form-control\" placeholder=\"3600\" style=\"width: 100px;\" value=\"" + record.ttl + "\" disabled>";
    html += "</div>";

    //buttons
    html += "<div class=\"form-group\" style=\"display: block; margin-bottom: 0px;\">";
    html += "<div id=\"data" + id + "\" data-record-name=\"" + record.name + "\" data-record-value=\"" + record.rData.value + "\" style=\"display: none;\"></div>";
    html += "<button id=\"btnEdit" + id + "\" type=\"button\" class=\"btn btn-primary\" data-id=\"" + id + "\" onclick=\"return editResourceRecord(this);\" style=\"margin-right: 10px;\">Edit</button>";
    html += "<button id=\"btnUpdate" + id + "\" type=\"submit\" class=\"btn btn-primary\" data-loading-text=\"Updating...\" data-id=\"" + id + "\" onclick=\"return updateResourceRecord(this);\" style=\"margin-right: 10px; display: none;\">Update</button>";
    html += "<button id=\"btnCancelEdit" + id + "\" type=\"button\" class=\"btn btn-default\" data-id=\"" + id + "\" onclick=\"return cancelEditResourceRecord(this);\" style=\"margin-right: 10px; display: none;\">Cancel</button>";
    html += "<button id=\"btnDelete" + id + "\" type=\"button\" class=\"btn btn-warning\" data-loading-text=\"Deleting...\" data-id=\"" + id + "\" onclick=\"return deleteResourceRecord(this);\">Delete</button>";
    html += "</div>";

    html += "</form>";
    html += "</li>";

    return html;
}

function renderMXResourceRecord(record, domain) {

    var id = Math.floor(Math.random() * 10000);

    var html = "<li id=\"li" + id + "\" class=\"list-group-item resource-record\">";
    html += "<form class=\"form-inline\">";

    //label
    html += "<div class=\"form-group\">";
    html += "<label for=\"optType" + id + "\">Type</label>";
    html += "<select id=\"optType" + id + "\" class=\"form-control\" disabled>";
    html += "<option selected>MX</option>";
    html += "</select>";
    html += "</div>";

    //name
    var name = record.name.toLowerCase();

    if (name === domain)
        name = "@";
    else
        name = name.replace("." + domain, "");

    html += "<div class=\"form-group\">";
    html += "<label for=\"txtName" + id + "\">Name</label>";
    html += "<input id=\"txtName" + id + "\" type=\"text\" class=\"form-control\" placeholder=\"@\" style=\"width: 136px;\" value=\"" + name + "\" disabled>";
    html += "</div>";

    //exchange
    html += "<div class=\"form-group\">";
    html += "<label for=\"txtExchange" + id + "\">Exchange</label>";
    html += "<input id=\"txtExchange" + id + "\" type=\"text\" class=\"form-control\" placeholder=\"mx1.example.com\" style=\"width: 250px;\" value=\"" + record.rData.value + "\" disabled>";
    html += "</div>";

    //preference
    html += "<div class=\"form-group\">";
    html += "<label for=\"txtPreference" + id + "\">Preference</label>";
    html += "<input id=\"txtPreference" + id + "\" type=\"number\" class=\"form-control\" placeholder=\"1\" style=\"width: 90px;\" value=\"" + record.rData.preference + "\" disabled>";
    html += "</div>";

    //ttl
    html += "<div class=\"form-group\">";
    html += "<label for=\"txtTtl" + id + "\">TTL</label>";
    html += "<input id=\"txtTtl" + id + "\" type=\"number\" class=\"form-control\" placeholder=\"3600\" style=\"width: 100px;\" value=\"" + record.ttl + "\" disabled>";
    html += "</div>";

    //buttons
    html += "<div class=\"form-group\" style=\"display: block; margin-bottom: 0px;\">";
    html += "<div id=\"data" + id + "\" data-record-name=\"" + record.name + "\" data-record-value=\"" + record.rData.value + "\" style=\"display: none;\"></div>";
    html += "<button id=\"btnEdit" + id + "\" type=\"button\" class=\"btn btn-primary\" data-id=\"" + id + "\" onclick=\"return editResourceRecord(this);\" style=\"margin-right: 10px;\">Edit</button>";
    html += "<button id=\"btnUpdate" + id + "\" type=\"submit\" class=\"btn btn-primary\" data-loading-text=\"Updating...\" data-id=\"" + id + "\" onclick=\"return updateResourceRecord(this);\" style=\"margin-right: 10px; display: none;\">Update</button>";
    html += "<button id=\"btnCancelEdit" + id + "\" type=\"button\" class=\"btn btn-default\" data-id=\"" + id + "\" onclick=\"return cancelEditResourceRecord(this);\" style=\"margin-right: 10px; display: none;\">Cancel</button>";
    html += "<button id=\"btnDelete" + id + "\" type=\"button\" class=\"btn btn-warning\" data-loading-text=\"Deleting...\" data-id=\"" + id + "\" onclick=\"return deleteResourceRecord(this);\">Delete</button>";
    html += "</div>";

    html += "</form>";
    html += "</li>";

    return html;
}

function renderSOAResourceRecord(record, domain) {

    var id = Math.floor(Math.random() * 10000);

    var html = "<li id=\"li" + id + "\" class=\"list-group-item resource-record\">";
    html += "<form class=\"form-inline\">";

    //label
    html += "<div class=\"form-group\">";
    html += "<label for=\"optType" + id + "\">Type</label>";
    html += "<select id=\"optType" + id + "\" class=\"form-control\" disabled>";
    html += "<option selected>SOA</option>";
    html += "</select>";
    html += "</div>";

    //name
    var name = record.name.toLowerCase();

    if (name === domain)
        name = "@";
    else
        name = name.replace("." + domain, "");

    html += "<div class=\"form-group\">";
    html += "<label for=\"txtName" + id + "\">Name</label>";
    html += "<input id=\"txtName" + id + "\" type=\"text\" class=\"form-control\" placeholder=\"@\" style=\"width: 70px;\" value=\"" + name + "\" disabled>";
    html += "</div>";

    //master name server
    html += "<div class=\"form-group\">";
    html += "<label for=\"txtMasterNameServer" + id + "\">Master Name Server</label>";
    html += "<input id=\"txtMasterNameServer" + id + "\"type=\"text\" class=\"form-control\" placeholder=\"value\" style=\"width: 300px;\" value=\"" + record.rData.masterNameServer + "\" disabled>";
    html += "</div>";

    //responsible person
    html += "<div class=\"form-group\">";
    html += "<label for=\"txtResponsiblePerson" + id + "\">Responsible Person</label>";
    html += "<input id=\"txtResponsiblePerson" + id + "\" type=\"text\" class=\"form-control\" placeholder=\"value\" style=\"width: 220px;\" value=\"" + record.rData.responsiblePerson + "\" disabled>";
    html += "</div>";

    //serial
    html += "<div class=\"form-group\">";
    html += "<label for=\"txtSerial" + id + "\">Serial</label>";
    html += "<input id=\"txtSerial" + id + "\" type=\"number\" class=\"form-control\" placeholder=\"value\" style=\"width: 150px;\" value=\"" + record.rData.serial + "\" disabled>";
    html += "</div>";

    //refresh
    html += "<div class=\"form-group\">";
    html += "<label for=\"txtRefresh" + id + "\">Refresh</label>";
    html += "<input id=\"txtRefresh" + id + "\" type=\"number\" class=\"form-control\" placeholder=\"value\" style=\"width: 100px;\" value=\"" + record.rData.refresh + "\" disabled>";
    html += "</div>";

    //retry
    html += "<div class=\"form-group\">";
    html += "<label for=\"txtRetry" + id + "\">Retry</label>";
    html += "<input id=\"txtRetry" + id + "\" type=\"number\" class=\"form-control\" placeholder=\"value\" style=\"width: 100px;\" value=\"" + record.rData.retry + "\" disabled>";
    html += "</div>";

    //expire
    html += "<div class=\"form-group\">";
    html += "<label for=\"txtExpire" + id + "\">Expire</label>";
    html += "<input id=\"txtExpire" + id + "\" type=\"number\" class=\"form-control\" placeholder=\"value\" style=\"width: 100px;\" value=\"" + record.rData.expire + "\" disabled>";
    html += "</div>";

    //minimum
    html += "<div class=\"form-group\">";
    html += "<label for=\"txtMinimum" + id + "\">Minimum</label>";
    html += "<input id=\"txtMinimum" + id + "\" type=\"number\" class=\"form-control\" placeholder=\"value\" style=\"width: 100px;\" value=\"" + record.rData.minimum + "\" disabled>";
    html += "</div>";

    //ttl
    html += "<div class=\"form-group\">";
    html += "<label for=\"txtTtl" + id + "\">TTL</label>";
    html += "<input id=\"txtTtl" + id + "\" type=\"number\" class=\"form-control\" placeholder=\"3600\" style=\"width: 100px;\" value=\"" + record.ttl + "\" disabled>";
    html += "</div>";

    //buttons
    html += "<div class=\"form-group\" style=\"display: block; margin-bottom: 0px;\">";
    html += "<button id=\"btnEdit" + id + "\" type=\"button\" class=\"btn btn-primary\" data-id=\"" + id + "\" onclick=\"return editResourceRecord(this);\" style=\"margin-right: 10px;\">Edit</button>";
    html += "<button id=\"btnUpdate" + id + "\" type=\"submit\" class=\"btn btn-primary\" data-loading-text=\"Updating...\" data-id=\"" + id + "\" onclick=\"return updateResourceRecord(this);\" style=\"margin-right: 10px; display: none;\">Update</button>";
    html += "<button id=\"btnCancelEdit" + id + "\" type=\"button\" class=\"btn btn-default\" data-id=\"" + id + "\" onclick=\"return cancelEditResourceRecord(this);\" style=\"margin-right: 10px; display: none;\">Cancel</button>";
    html += "</div>";

    html += "</form>";
    html += "</li>";

    return html;
}

function renderSRVResourceRecord(record, domain) {

    var id = Math.floor(Math.random() * 10000);

    var html = "<li id=\"li" + id + "\" class=\"list-group-item resource-record\">";
    html += "<form class=\"form-inline\">";

    //label
    html += "<div class=\"form-group\">";
    html += "<label for=\"optType" + id + "\">Type</label>";
    html += "<select id=\"optType" + id + "\" class=\"form-control\" disabled>";
    html += "<option selected>SRV</option>";
    html += "</select>";
    html += "</div>";

    //parse name, service and protocol
    var nameParts = record.name.toLowerCase().split(".");
    var name;
    var service = nameParts[0];
    var protocol = nameParts[1];

    for (var i = 2; i < nameParts.length; i++) {
        if (name == null)
            name = nameParts[i];
        else
            name += "." + nameParts[i];
    }

    if (name === domain)
        name = "@";
    else
        name = name.replace("." + domain, "");

    if (service.startsWith("_"))
        service = service.substr(1);

    if (protocol.startsWith("_"))
        protocol = protocol.substr(1);

    //name
    html += "<div class=\"form-group\">";
    html += "<label for=\"txtName" + id + "\">Name</label>";
    html += "<input id=\"txtName" + id + "\" type=\"text\" class=\"form-control\" placeholder=\"@\" style=\"width: 120px;\" value=\"" + name + "\" disabled>";
    html += "</div>";

    //service
    html += "<div class=\"form-group\">";
    html += "<label for=\"txtService" + id + "\">Service</label>";
    html += "<input id=\"txtService" + id + "\" type=\"text\" class=\"form-control\" placeholder=\"service\" style=\"width: 80px;\" value=\"" + service + "\" disabled>";
    html += "</div>";

    //protocol
    html += "<div class=\"form-group\">";
    html += "<label for=\"txtProtocol" + id + "\">Protocol</label>";
    html += "<input id=\"txtProtocol" + id + "\"type=\"text\" class=\"form-control\" placeholder=\"protocol\" style=\"width: 80px;\" value=\"" + protocol + "\" disabled>";
    html += "</div>";

    //priority
    html += "<div class=\"form-group\">";
    html += "<label for=\"txtPriority" + id + "\">Priority</label>";
    html += "<input id=\"txtPriority" + id + "\" type=\"number\" class=\"form-control\" placeholder=\"priority\" style=\"width: 80px;\" value=\"" + record.rData.priority + "\" disabled>";
    html += "</div>";

    //weight
    html += "<div class=\"form-group\">";
    html += "<label for=\"txtWeight" + id + "\">Weight</label>";
    html += "<input id=\"txtWeight" + id + "\" type=\"number\" class=\"form-control\" placeholder=\"weight\" style=\"width: 80px;\" value=\"" + record.rData.weight + "\" disabled>";
    html += "</div>";

    //port
    html += "<div class=\"form-group\">";
    html += "<label for=\"txtPort" + id + "\">Port</label>";
    html += "<input id=\"txtPort" + id + "\" type=\"number\" class=\"form-control\" placeholder=\"port\" style=\"width: 80px;\" value=\"" + record.rData.port + "\" disabled>";
    html += "</div>";

    //target
    html += "<div class=\"form-group\">";
    html += "<label for=\"txtTarget" + id + "\">Target</label>";
    html += "<input id=\"txtTarget" + id + "\" type=\"text\" class=\"form-control\" placeholder=\"target\" style=\"width: 280px;\" value=\"" + record.rData.value + "\" disabled>";
    html += "</div>";

    //ttl
    html += "<div class=\"form-group\">";
    html += "<label for=\"txtTtl" + id + "\">TTL</label>";
    html += "<input id=\"txtTtl" + id + "\" type=\"number\" class=\"form-control\" placeholder=\"3600\" style=\"width: 100px;\" value=\"" + record.ttl + "\" disabled>";
    html += "</div>";

    //buttons
    html += "<div class=\"form-group\" style=\"display: block; margin-bottom: 0px;\">";
    html += "<div id=\"data" + id + "\" data-record-name=\"" + record.name + "\" data-record-value=\"" + record.rData.value + "\" data-record-port=\"" + record.rData.port + "\" style=\"display: none;\"></div>";
    html += "<button id=\"btnEdit" + id + "\" type=\"button\" class=\"btn btn-primary\" data-id=\"" + id + "\" onclick=\"return editResourceRecord(this);\" style=\"margin-right: 10px;\">Edit</button>";
    html += "<button id=\"btnUpdate" + id + "\" type=\"submit\" class=\"btn btn-primary\" data-loading-text=\"Updating...\" data-id=\"" + id + "\" onclick=\"return updateResourceRecord(this);\" style=\"margin-right: 10px; display: none;\">Update</button>";
    html += "<button id=\"btnCancelEdit" + id + "\" type=\"button\" class=\"btn btn-default\" data-id=\"" + id + "\" onclick=\"return cancelEditResourceRecord(this);\" style=\"margin-right: 10px; display: none;\">Cancel</button>";
    html += "<button id=\"btnDelete" + id + "\" type=\"button\" class=\"btn btn-warning\" data-loading-text=\"Deleting...\" data-id=\"" + id + "\" onclick=\"return deleteResourceRecord(this);\">Delete</button>";
    html += "</div>";

    html += "</form>";
    html += "</li>";

    return html;
}

function renderAddResourceRecordForm(domain) {

    var html = "<li class=\"list-group-item\" id=\"addRecordFormItem\">";
    html += "<form class=\"form-inline\">";

    //label
    html += "<div class=\"form-group\">";
    html += "<label for=\"optAddRecordType\">Type</label>";
    html += "<select id=\"optAddRecordType\" class=\"form-control\" onchange=\"return modifyAddRecordForm();\">";
    html += "<option selected>A</option>";
    html += "<option>NS</option>";
    html += "<option>CNAME</option>";
    html += "<option>PTR</option>";
    html += "<option>MX</option>";
    html += "<option>TXT</option>";
    html += "<option>AAAA</option>";
    html += "<option>SRV</option>";
    html += "</select>";
    html += "</div>";

    //name
    html += "<div class=\"form-group\" id=\"divAddRecordName\">";
    html += "<label for=\"txtAddRecordName\">Name</label>";
    html += "<input id=\"txtAddRecordName\" type=\"text\" class=\"form-control\" placeholder=\"@\" style=\"width: 80px;\">";
    html += "</div>";

    //value
    html += "<div class=\"form-group\" id=\"divAddRecordValue\">";
    html += "<label for=\"txtAddRecordValue\">Value</label>";
    html += "<input id=\"txtAddRecordValue\" type=\"text\" class=\"form-control\" placeholder=\"value\" style=\"width: 290px;\">";
    html += "</div>";

    //value MX Exchange
    html += "<div class=\"form-group\" id=\"divAddRecordMXExchange\" style=\"display: none;\">";
    html += "<label for=\"txtAddRecordExchange\">Exchange</label>";
    html += "<input id=\"txtAddRecordExchange\" type=\"text\" class=\"form-control\" placeholder=\"value\" style=\"width: 220px;\">";
    html += "</div>";

    //value MX Preference
    html += "<div class=\"form-group\" id=\"divAddRecordMXPreference\" style=\"display: none;\">";
    html += "<label for=\"txtAddRecordPreference\">Preference</label>";
    html += "<input id=\"txtAddRecordPreference\" type=\"number\" class=\"form-control\" placeholder=\"value\" style=\"width: 90px;\">";
    html += "</div>";

    //value SRV Service
    html += "<div class=\"form-group\" id=\"divAddRecordSRVService\" style=\"display: none;\">";
    html += "<label for=\"txtAddRecordSRVService\">Service</label>";
    html += "<input id=\"txtAddRecordSRVService\" type=\"text\" class=\"form-control\" placeholder=\"service\" style=\"width: 80px;\">";
    html += "</div>";

    //value SRV Protocol
    html += "<div class=\"form-group\" id=\"divAddRecordSRVProtocol\" style=\"display: none;\">";
    html += "<label for=\"txtAddRecordSRVProtocol\">Protocol</label>";
    html += "<input id=\"txtAddRecordSRVProtocol\" type=\"text\" class=\"form-control\" placeholder=\"protocol\" style=\"width: 80px;\">";
    html += "</div>";

    //value SRV Priority
    html += "<div class=\"form-group\" id=\"divAddRecordSRVPriority\" style=\"display: none;\">";
    html += "<label for=\"txtAddRecordSRVPriority\">Priority</label>";
    html += "<input id=\"txtAddRecordSRVPriority\" type=\"number\" class=\"form-control\" placeholder=\"priority\" style=\"width: 90px;\">";
    html += "</div>";

    //value SRV Weight
    html += "<div class=\"form-group\" id=\"divAddRecordSRVWeight\" style=\"display: none;\">";
    html += "<label for=\"txtAddRecordSRVWeight\">Weight</label>";
    html += "<input id=\"txtAddRecordSRVWeight\" type=\"number\" class=\"form-control\" placeholder=\"weight\" style=\"width: 90px;\">";
    html += "</div>";

    //value SRV Port
    html += "<div class=\"form-group\" id=\"divAddRecordSRVPort\" style=\"display: none;\">";
    html += "<label for=\"txtAddRecordSRVPort\">Port</label>";
    html += "<input id=\"txtAddRecordSRVPort\" type=\"number\" class=\"form-control\" placeholder=\"port\" style=\"width: 80px;\">";
    html += "</div>";

    //value SRV Target
    html += "<div class=\"form-group\" id=\"divAddRecordSRVTarget\" style=\"display: none;\">";
    html += "<label for=\"txtAddRecordSRVTarget\">Target</label>";
    html += "<input id=\"txtAddRecordSRVTarget\" type=\"text\" class=\"form-control\" placeholder=\"target\" style=\"width: 280px;\">";
    html += "</div>";

    //ttl
    html += "<div class=\"form-group\">";
    html += "<label for=\"txtAddRecordTtl\">TTL</label>";
    html += "<input id=\"txtAddRecordTtl\" type=\"number\" class=\"form-control\" placeholder=\"3600\" style=\"width: 100px;\">";
    html += "</div>";

    //buttons
    html += "<div class=\"form-group\" style=\"display: block; margin-bottom: 0px;\">";
    html += "<button id=\"btnAddRecord\" type=\"submit\" class=\"btn btn-primary\" data-loading-text=\"Adding...\" onclick=\"return addResourceRecord();\">Add</button>";
    html += "</div>";

    html += "</form>";
    html += "</li>";

    return html;
}

function editResourceRecord(btnObj) {

    var btnEdit = $(btnObj);
    var id = btnEdit.attr("data-id");

    var type = $("#optType" + id).val();

    $("#btnEdit" + id).hide();
    $("#btnUpdate" + id).show();
    $("#btnCancelEdit" + id).show();

    switch (type) {
        case "MX":
            $("#btnDelete" + id).hide();

            $("#txtName" + id).prop("disabled", false);
            $("#txtExchange" + id).prop("disabled", false);
            $("#txtPreference" + id).prop("disabled", false);
            break;

        case "SOA":
            $("#txtMasterNameServer" + id).prop("disabled", false);
            $("#txtResponsiblePerson" + id).prop("disabled", false);
            $("#txtSerial" + id).prop("disabled", false);
            $("#txtRefresh" + id).prop("disabled", false);
            $("#txtRetry" + id).prop("disabled", false);
            $("#txtExpire" + id).prop("disabled", false);
            $("#txtMinimum" + id).prop("disabled", false);
            break;

        case "SRV":
            $("#btnDelete" + id).hide();

            $("#txtName" + id).prop("disabled", false);
            $("#txtService" + id).prop("disabled", false);
            $("#txtProtocol" + id).prop("disabled", false);
            $("#txtPriority" + id).prop("disabled", false);
            $("#txtWeight" + id).prop("disabled", false);
            $("#txtPort" + id).prop("disabled", false);
            $("#txtTarget" + id).prop("disabled", false);
            break;

        default:
            $("#btnDelete" + id).hide();

            $("#txtName" + id).prop("disabled", false);
            $("#txtValue" + id).prop("disabled", false);
            break;
    }

    $("#txtTtl" + id).prop("disabled", false);
}

function cancelEditResourceRecord(btnObj) {

    var btnCancelEdit = $(btnObj);
    var id = btnCancelEdit.attr("data-id");

    var type = $("#optType" + id).val();

    $("#btnEdit" + id).show();
    $("#btnUpdate" + id).hide();
    $("#btnCancelEdit" + id).hide();

    switch (type) {
        case "MX":
            $("#btnDelete" + id).show();

            $("#txtName" + id).prop("disabled", true);
            $("#txtExchange" + id).prop("disabled", true);
            $("#txtPreference" + id).prop("disabled", true);
            break;

        case "SOA":
            $("#txtMasterNameServer" + id).prop("disabled", true);
            $("#txtResponsiblePerson" + id).prop("disabled", true);
            $("#txtSerial" + id).prop("disabled", true);
            $("#txtRefresh" + id).prop("disabled", true);
            $("#txtRetry" + id).prop("disabled", true);
            $("#txtExpire" + id).prop("disabled", true);
            $("#txtMinimum" + id).prop("disabled", true);
            break;

        case "SRV":
            $("#btnDelete" + id).show();

            $("#txtName" + id).prop("disabled", true);
            $("#txtService" + id).prop("disabled", true);
            $("#txtProtocol" + id).prop("disabled", true);
            $("#txtPriority" + id).prop("disabled", true);
            $("#txtWeight" + id).prop("disabled", true);
            $("#txtPort" + id).prop("disabled", true);
            $("#txtTarget" + id).prop("disabled", true);
            break;

        default:
            $("#btnDelete" + id).show();

            $("#txtName" + id).prop("disabled", true);
            $("#txtValue" + id).prop("disabled", true);
            break;
    }

    $("#txtTtl" + id).prop("disabled", true);
}

function modifyAddRecordForm() {

    var type = $("#optAddRecordType").val();

    switch (type) {
        case "MX":
            $("#divAddRecordName").show();
            $("#divAddRecordValue").hide();

            $("#divAddRecordMXExchange").show();
            $("#divAddRecordMXPreference").show();

            $("#divAddRecordSRVService").hide();
            $("#divAddRecordSRVProtocol").hide();
            $("#divAddRecordSRVPriority").hide();
            $("#divAddRecordSRVWeight").hide();
            $("#divAddRecordSRVPort").hide();
            $("#divAddRecordSRVTarget").hide();
            break;

        case "SRV":
            $("#divAddRecordName").show();
            $("#divAddRecordValue").hide();

            $("#divAddRecordMXExchange").hide();
            $("#divAddRecordMXPreference").hide();

            $("#divAddRecordSRVService").show();
            $("#divAddRecordSRVProtocol").show();
            $("#divAddRecordSRVPriority").show();
            $("#divAddRecordSRVWeight").show();
            $("#divAddRecordSRVPort").show();
            $("#divAddRecordSRVTarget").show();
            break;

        default:
            $("#divAddRecordName").show();
            $("#divAddRecordValue").show();

            $("#divAddRecordMXExchange").hide();
            $("#divAddRecordMXPreference").hide();

            $("#divAddRecordSRVService").hide();
            $("#divAddRecordSRVProtocol").hide();
            $("#divAddRecordSRVPriority").hide();
            $("#divAddRecordSRVWeight").hide();
            $("#divAddRecordSRVPort").hide();
            $("#divAddRecordSRVTarget").hide();
            break;
    }
}

function addResourceRecord() {

    var domain = $("#spanZoneViewerTitle").text();

    var type = $("#optAddRecordType").val();
    var subDomain = $("#txtAddRecordName").val();
    var ttl = $("#txtAddRecordTtl").val();

    if ((subDomain === null) || (subDomain === "")) {
        subDomain = "@";
    }

    var name;

    if (subDomain === "@")
        name = domain;
    else
        name = subDomain + "." + domain;

    var value;
    var preference;

    var priority;
    var weight;
    var port;

    switch (type) {
        case "MX":
            value = $("#txtAddRecordExchange").val();
            preference = $("#txtAddRecordPreference").val();

            if ((value === null) || (value === "")) {
                showAlert("warning", "Missing!", "Please enter an mail exchange domain name into the exchange field.");
                return false;
            }

            if ((preference === null) || (preference === "")) {
                preference = 1;
            }
            break;

        case "SRV":
            var service = $("#txtAddRecordSRVService").val();
            var protocol = $("#txtAddRecordSRVProtocol").val();

            if (!service.startsWith("_"))
                service = "_" + service;

            if (!protocol.startsWith("_"))
                protocol = "_" + protocol;

            name = service + "." + protocol + "." + name;

            priority = $("#txtAddRecordSRVPriority").val();
            weight = $("#txtAddRecordSRVWeight").val();
            port = $("#txtAddRecordSRVPort").val();
            value = $("#txtAddRecordSRVTarget").val();
            break;

        default:
            value = $("#txtAddRecordValue").val();

            if ((value === null) || (value === "")) {
                showAlert("warning", "Missing!", "Please enter a suitable value into the value field.");
                return false;
            }
            break;
    }

    if ((ttl === null) || (ttl === "")) {
        ttl = 3600;
    }

    var apiUrl = "/api/addRecord?token=" + token + "&domain=" + name + "&type=" + type + "&ttl=" + ttl + "&value=" + value;

    switch (type) {
        case "MX":
            apiUrl += "&preference=" + preference;
            break;

        case "SRV":
            apiUrl += "&priority=" + priority + "&weight=" + weight + "&port=" + port;
            break;
    }

    var btn = $("#btnAddRecord").button('loading');

    HTTPRequest({
        url: apiUrl,
        success: function (responseJSON) {
            $("#txtAddRecordName").val("");
            $("#txtAddRecordValue").val("");

            $("#txtAddRecordExchange").val("");
            $("#txtAddRecordPreference").val("");

            $("#txtAddRecordSRVService").val("");
            $("#txtAddRecordSRVProtocol").val("");
            $("#txtAddRecordSRVPriority").val("");
            $("#txtAddRecordSRVWeight").val("");
            $("#txtAddRecordSRVPort").val("");
            $("#txtAddRecordSRVTarget").val("");

            var record = { "name": name, "type": type, "ttl": ttl, "rData": { "value": value, "preference": preference, "priority": priority, "weight": weight, "port": port } };
            var html = renderResourceRecord(record, domain);

            $("#addRecordFormItem").before(html);
            btn.button('reset');

            showAlert("success", "Record Added!", "Resource record was added successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
            showPageLogin();
        }
    });

    return false;
}

function deleteResourceRecord(objBtn) {

    var btnDelete = $(objBtn);
    var id = btnDelete.attr("data-id");
    var divData = $("#data" + id);

    var type = $("#optType" + id).val();
    var name = divData.attr("data-record-name");
    var value = divData.attr("data-record-value");

    if (!confirm("Are you sure to permanently delete the " + type + " record '" + name + "' with value '" + value + "'?"))
        return false;

    var apiUrl = "/api/deleteRecord?token=" + token + "&domain=" + name + "&type=" + type + "&value=" + value;

    if (type === "SRV") {
        var port = $("#txtPort" + id).val();

        apiUrl += "&port=" + port;
    }

    btnDelete.button('loading');

    HTTPRequest({
        url: apiUrl,
        success: function (responseJSON) {
            $("#li" + id).remove();

            showAlert("success", "Record Deleted!", "Resource record was deleted successfully.");
        },
        error: function () {
            btnDelete.button('reset');
        },
        invalidToken: function () {
            btnDelete.button('reset');
            showPageLogin();
        }
    });

    return false;
}

function updateResourceRecord(objBtn) {

    var btnUpdate = $(objBtn);
    var id = btnUpdate.attr("data-id");
    var divData = $("#data" + id);

    var domain = $("#spanZoneViewerTitle").text();
    var type = $("#optType" + id).val();

    var newName = $("#txtName" + id).val();
    var ttl = $("#txtTtl" + id).val();

    if ((newName === null) || (newName === "")) {
        showAlert("warning", "Missing!", "Please enter a sub domain name into the name field.");
        return false;
    }

    if (newName === "@")
        newName = domain;
    else
        newName = newName + "." + domain;

    if ((ttl === null) || (ttl === "")) {
        ttl = 3600;
    }

    var oldName = divData.attr("data-record-name");
    var oldValue = divData.attr("data-record-value");
    var newValue;

    var preference;

    var masterNameServer;
    var responsiblePerson;
    var serial;
    var refresh;
    var retry;
    var expire;
    var minimum;

    var oldPort;
    var priority;
    var weight;
    var port;

    switch (type) {
        case "MX":
            newValue = $("#txtExchange" + id).val();
            preference = $("#txtPreference" + id).val();

            if ((newValue === null) || (newValue === "")) {
                showAlert("warning", "Missing!", "Please enter an mail exchange domain name into the exchange field.");
                return false;
            }

            if ((preference === null) || (preference === "")) {
                preference = 1;
            }
            break;

        case "SOA":
            masterNameServer = $("#txtMasterNameServer" + id).val();
            responsiblePerson = $("#txtResponsiblePerson" + id).val();
            serial = $("#txtSerial" + id).val();
            refresh = $("#txtRefresh" + id).val();
            retry = $("#txtRetry" + id).val();
            expire = $("#txtExpire" + id).val();
            minimum = $("#txtMinimum" + id).val();

            if ((masterNameServer === null) || (masterNameServer === "")) {
                showAlert("warning", "Missing!", "Please enter a master name server domain name.");
                return false;
            }

            if ((responsiblePerson === null) || (responsiblePerson === "")) {
                showAlert("warning", "Missing!", "Please enter a responsible person email address in domain name format.");
                return false;
            }

            if ((serial === null) || (serial === "")) {
                showAlert("warning", "Missing!", "Please enter a serial number.");
                return false;
            }

            if ((refresh === null) || (refresh === "")) {
                showAlert("warning", "Missing!", "Please enter a refresh value.");
                return false;
            }

            if ((retry === null) || (retry === "")) {
                showAlert("warning", "Missing!", "Please enter a retry value.");
                return false;
            }

            if ((expire === null) || (expire === "")) {
                showAlert("warning", "Missing!", "Please enter an expire value.");
                return false;
            }

            if ((minimum === null) || (minimum === "")) {
                showAlert("warning", "Missing!", "Please enter a minimum value.");
                return false;
            }
            break;

        case "SRV":
            var service = $("#txtService" + id).val();
            var protocol = $("#txtProtocol" + id).val();

            if (!service.startsWith("_"))
                service = "_" + service;

            if (!protocol.startsWith("_"))
                protocol = "_" + protocol;

            newName = service + "." + protocol + "." + newName;

            oldPort = divData.attr("data-record-port");

            priority = $("#txtPriority" + id).val();
            weight = $("#txtWeight" + id).val();
            port = $("#txtPort" + id).val();
            newValue = $("#txtTarget" + id).val();
            break;

        default:
            newValue = $("#txtValue" + id).val();

            if ((newValue === null) || (newValue === "")) {
                showAlert("warning", "Missing!", "Please enter a suitable value into the value field.");
                return false;
            }
            break;
    }

    var apiUrl = "/api/updateRecord?token=" + token + "&type=" + type + "&domain=" + newName + "&oldDomain=" + oldName + "&value=" + newValue + "&oldValue=" + oldValue + "&ttl=" + ttl;

    switch (type) {
        case "MX":
            apiUrl += "&preference=" + preference;
            break;

        case "SOA":
            apiUrl += "&masterNameServer=" + masterNameServer + "&responsiblePerson=" + responsiblePerson + "&serial=" + serial + "&refresh=" + refresh + "&retry=" + retry + "&expire=" + expire + "&minimum=" + minimum;
            break;

        case "SRV":
            apiUrl += "&oldPort=" + oldPort + "&priority=" + priority + "&weight=" + weight + "&port=" + port;
            break;
    }

    btnUpdate.button('loading');

    HTTPRequest({
        url: apiUrl,
        success: function (responseJSON) {

            switch (type) {
                case "SOA":
                    break;

                case "SRV":
                    divData.attr("data-record-name", newName);
                    divData.attr("data-record-value", newValue);
                    divData.attr("data-record-port", port);
                    break;

                default:
                    divData.attr("data-record-name", newName);
                    divData.attr("data-record-value", newValue);
                    break;
            }

            btnUpdate.button('reset');
            cancelEditResourceRecord(objBtn);

            showAlert("success", "Record Updated!", "Resource record was updated successfully.");
        },
        error: function () {
            btnUpdate.button('reset');
        },
        invalidToken: function () {
            btnUpdate.button('reset');
            showPageLogin();
        }
    });

    return false;
}

function resolveQuery(importRecords) {

    if (importRecords == null)
        importRecords = false;

    var server = $("#txtDnsClientNameServer").val();
    var domain = $("#txtDnsClientDomain").val();
    var type = $("#optDnsClientType").val();
    var protocol = $("#optDnsClientProtocol").val();

    {
        var i = server.indexOf("(");
        if (i > -1) {
            var j = server.indexOf(")");
            server = server.substring(i + 1, j);
        }
    }

    server = server.trim();

    if ((server === null) || (server === "")) {
        showAlert("warning", "Missing!", "Please enter a valid Name Server.");
        return false;
    }

    if ((domain === null) || (domain === "")) {
        showAlert("warning", "Missing!", "Please enter a domain name to query.");
        return false;
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
        if (!confirm("Importing all the records from the result of this query will overwrite existing records in the zone '" + domain + "'.\n\nAre you sure you want to import all records?"))
            return false;
    }

    var btn = $(importRecords ? "#btnDnsClientImport" : "#btnDnsClientResolve").button('loading');
    var btnOther = $(importRecords ? "#btnDnsClientResolve" : "#btnDnsClientImport").prop("disabled", true);

    var divDnsClientLoader = $("#divDnsClientLoader");
    var preDnsClientOutput = $("#preDnsClientOutput");

    preDnsClientOutput.hide();
    divDnsClientLoader.show();

    HTTPRequest({
        url: "/api/resolveQuery?token=" + token + "&server=" + server + "&domain=" + domain + "&type=" + type + "&protocol=" + protocol + (importRecords ? "&import=true" : ""),
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
        objLoaderPlaceholder: divDnsClientLoader
    });

    //add server name to list if doesnt exists
    var txtServerName = $("#txtDnsClientNameServer").val();
    var containsServer = false;

    $("#optDnsClientNameServers a").each(function () {
        if ($(this).html() === txtServerName)
            containsServer = true;
    });

    if (!containsServer)
        $("#optDnsClientNameServers").prepend('<li><a href="#" onclick="return false;">' + txtServerName + '</a></li>');

    return false;
}

function refreshLogFilesList() {

    var lstLogFiles = $("#lstLogFiles");

    HTTPRequest({
        url: "/api/listLogs?token=" + token,
        success: function (responseJSON) {
            var logFiles = responseJSON.response.logFiles;

            var list = "";

            for (var i = 0; i < logFiles.length; i++) {
                var logFile = logFiles[i];

                list += "<div class=\"log\"><a href=\"#\" onclick=\"return viewLog('" + logFile.fileName + "');\">" + logFile.fileName + " [" + logFile.size + "]</a></div>"
            }

            lstLogFiles.html(list);
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: lstLogFiles
    });

    return false;
}

function viewLog(logFile) {

    var divLogViewer = $("#divLogViewer");
    var txtLogViewerTitle = $("#txtLogViewerTitle");
    var divLogViewerLoader = $("#divLogViewerLoader");
    var preLogViewerBody = $("#preLogViewerBody");

    txtLogViewerTitle.text(logFile);

    preLogViewerBody.hide();
    divLogViewerLoader.show();
    divLogViewer.show();

    HTTPGetFileRequest({
        url: "/log/" + logFile + "?token=" + token,
        success: function (response) {

            divLogViewerLoader.hide();

            preLogViewerBody.text(response);
            preLogViewerBody.show();
        },
        objLoaderPlaceholder: divLogViewerLoader
    });

    return false;
}

function downloadLog() {

    var logFile = $("#txtLogViewerTitle").text();

    window.open("/log/" + logFile + "?token=" + token, "_blank");

    return false;
}

function deleteLog() {

    var logFile = $("#txtLogViewerTitle").text();

    if (!confirm("Are you sure you want to permanently delete the log file '" + logFile + "'?"))
        return false;

    var btn = $("#btnDeleteLog").button('loading');

    HTTPRequest({
        url: "/api/deleteLog?token=" + token + "&log=" + logFile,
        success: function (responseJSON) {
            refreshLogFilesList();

            $("#divLogViewer").hide();
            btn.button('reset');

            showAlert("success", "Log Deleted!", "Log file was deleted successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
            showPageLogin();
        }
    });

    return false;
}
