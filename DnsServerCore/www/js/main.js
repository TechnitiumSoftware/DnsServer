
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
    $("#pageMain").show();

    refreshZonesList();
    loadDnsSettings();

    refreshZonesTimerHandle = setInterval(function () { refreshZonesList(true); }, 10000);
}

$(function () {
    var headerHtml = $("#header").html();

    $("#header").html("<div class=\"title\"><a href=\"/\"><img src=\"/img/logo25x25.png\" alt=\"Technitium Logo\" /><span class=\"text\" style=\"color: #ffffff;\">Technitium</span></a>" + headerHtml + "</div>");
    $("#footer").html("<div class=\"content\"><a href=\"https://technitium.com\" target=\"_blank\">Technitium</a> | <a href=\"http://blog.technitium.com\" target=\"_blank\">Blog</a> | <a href=\"https://github.com/TechnitiumSoftware/DnsServer\" target=\"_blank\"><i class=\"fa fa-github\"></i>&nbsp;GitHub</a> | <a href=\"https://technitium.com/aboutus.html\" target=\"_blank\">About</a></div>");

    showPageLogin();
});

function login() {

    var username = $("#txtUser").val();
    var password = $("#txtPass").val();

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
        },
        error: function () {
            btn.button('reset');
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

function loadDnsSettings() {

    var divDnsSettingsLoader = $("#divDnsSettingsLoader");
    var divDnsSettings = $("#divDnsSettings");

    divDnsSettings.hide();
    divDnsSettingsLoader.show();

    HTTPRequest({
        url: "/api/getDnsSettings?token=" + token,
        success: function (responseJSON) {

            $("#txtServerDomain").val(responseJSON.response.serverDomain);
            $("#lblServerDomain").text(" - " + responseJSON.response.serverDomain);

            $("#txtWebServicePort").val(responseJSON.response.webServicePort);

            $("#chkPreferIPv6").prop("checked", responseJSON.response.preferIPv6);
            $("#chkAllowRecursion").prop("checked", responseJSON.response.allowRecursion);

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
    var allowRecursion = $("#chkAllowRecursion").prop('checked');
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

    var btn = $("#btnSaveDnsSettings").button('loading');

    HTTPRequest({
        url: "/api/setDnsSettings?token=" + token + "&serverDomain=" + serverDomain + "&webServicePort=" + webServicePort + "&preferIPv6=" + preferIPv6 + "&allowRecursion=" + allowRecursion + "&forwarders=" + forwarders,
        success: function (responseJSON) {
            $("#lblServerDomain").text(" - " + serverDomain);

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

function refreshZonesList(hideLoader) {

    var lstZones = $("#lstZones");
    var divLoader;

    if ((hideLoader == null) || !hideLoader)
        divLoader = lstZones;

    HTTPRequest({
        url: "/api/listZones?token=" + token,
        success: function (responseJSON) {
            var zones = responseJSON.response.zones;

            var list = "";

            for (var i = 0; i < zones.length; i++) {
                var zoneName = htmlEncode(zones[i]);

                list += "<div style=\"padding: 4px; \"><a href=\"#\" onclick=\"return viewZone('" + zoneName + "');\">" + zoneName + "</a></div>"
            }

            lstZones.html(list);
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divLoader
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

            $("#txtAddZone").val("");
            btn.button('reset');

            showAlert("success", "Zone Added!", "Zone was added successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            showPageLogin();
        }
    });

    return false;
}

function deleteZone(domain) {

    var domain = $("#txtZoneViewerTitle").text();

    if (!confirm("Are you sure to permanently delete the zone '" + domain + "' and all its records?"))
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
            showPageLogin();
        }
    });

    return false;
}

function viewZone(domain) {

    var divZoneViewer = $("#divZoneViewer");
    var txtZoneViewerTitle = $("#txtZoneViewerTitle");
    var divZoneViewerBody = $("#divZoneViewerBody");
    var divZoneViewerLoader = $("#divZoneViewerLoader");

    txtZoneViewerTitle.text(domain);
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
    html += "<input id=\"txtName" + id + "\" type=\"text\" class=\"form-control\" placeholder=\"@\" style=\"width: 136px;\" value=\"" + name + "\" disabled>";
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
    html += "</select>";
    html += "</div>";

    //name
    html += "<div class=\"form-group\">";
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
            $("#divAddRecordValue").hide();
            $("#divAddRecordMXExchange").show();
            $("#divAddRecordMXPreference").show();
            break;

        default:
            $("#divAddRecordValue").show();
            $("#divAddRecordMXExchange").hide();
            $("#divAddRecordMXPreference").hide();
            break;
    }
}

function addResourceRecord() {

    var domain = $("#txtZoneViewerTitle").text();

    var type = $("#optAddRecordType").val();
    var subDomain = $("#txtAddRecordName").val();
    var ttl = $("#txtAddRecordTtl").val();

    if ((subDomain === null) || (subDomain === "")) {
        showAlert("warning", "Missing!", "Please enter a sub domain name into the name field.");
        return false;
    }

    var value;
    var preference;

    if (type === "MX") {

        value = $("#txtAddRecordExchange").val();
        preference = $("#txtAddRecordPreference").val();

        if ((value === null) || (value === "")) {
            showAlert("warning", "Missing!", "Please enter an mail exchange domain name into the exchange field.");
            return false;
        }

        if ((preference === null) || (preference === "")) {
            preference = 1;
        }

    } else {

        value = $("#txtAddRecordValue").val();

        if ((value === null) || (value === "")) {
            showAlert("warning", "Missing!", "Please enter a suitable value into the value field.");
            return false;
        }
    }

    if ((ttl === null) || (ttl === "")) {
        ttl = 3600;
    }

    var name;

    if (subDomain === "@")
        name = domain;
    else
        name = subDomain + "." + domain;

    var apiUrl = "/api/addRecord?token=" + token + "&domain=" + name + "&type=" + type + "&ttl=" + ttl + "&value=" + value;

    if (type === "MX")
        apiUrl += "&preference=" + preference;

    var btn = $("#btnAddRecord").button('loading');

    HTTPRequest({
        url: apiUrl,
        success: function (responseJSON) {
            $("#txtAddRecordName").val("");
            $("#txtAddRecordValue").val("");
            $("#txtAddRecordExchange").val("");
            $("#txtAddRecordPreference").val("");

            var record = { "name": name, "type": type, "ttl": ttl, "rData": { "value": value, "preference": preference } };
            var html = renderResourceRecord(record, domain);

            $("#addRecordFormItem").before(html);
            btn.button('reset');

            showAlert("success", "Record Added!", "Resource record was added successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
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

    btnDelete.button('loading');

    HTTPRequest({
        url: "/api/deleteRecord?token=" + token + "&domain=" + name + "&type=" + type + "&value=" + value,
        success: function (responseJSON) {
            $("#li" + id).remove();

            showAlert("success", "Record Deleted!", "Resource record was deleted successfully.");
        },
        error: function () {
            btnDelete.button('reset');
        },
        invalidToken: function () {
            showPageLogin();
        }
    });

    return false;
}

function updateResourceRecord(objBtn) {

    var btnUpdate = $(objBtn);
    var id = btnUpdate.attr("data-id");
    var divData = $("#data" + id);

    var domain = $("#txtZoneViewerTitle").text();
    var type = $("#optType" + id).val();

    var oldName;
    var oldValue;

    if (type !== "SOA") {
        oldName = divData.attr("data-record-name");
        oldValue = divData.attr("data-record-value");
    }

    var newName = $("#txtName" + id).val();
    var ttl = $("#txtTtl" + id).val();

    if ((newName === null) || (newName === "")) {
        showAlert("warning", "Missing!", "Please enter a sub domain name into the name field.");
        return false;
    }

    var newValue;
    var preference;

    var masterNameServer;
    var responsiblePerson;
    var serial;
    var refresh;
    var retry;
    var expire;
    var minimum;

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

        default:
            newValue = $("#txtValue" + id).val();

            if ((newValue === null) || (newValue === "")) {
                showAlert("warning", "Missing!", "Please enter a suitable value into the value field.");
                return false;
            }
            break;
    }

    if ((ttl === null) || (ttl === "")) {
        ttl = 3600;
    }

    if (newName === "@")
        newName = domain;
    else
        newName = newName + "." + domain;

    var apiUrl = "/api/updateRecord?token=" + token + "&type=" + type + "&domain=" + newName + "&oldDomain=" + oldName + "&value=" + newValue + "&oldValue=" + oldValue + "&ttl=" + ttl;

    switch (type) {
        case "MX":
            apiUrl += "&preference=" + preference;
            break;

        case "SOA":
            apiUrl += "&masterNameServer=" + masterNameServer + "&responsiblePerson=" + responsiblePerson + "&serial=" + serial + "&refresh=" + refresh + "&retry=" + retry + "&expire=" + expire + "&minimum=" + minimum;
            break;
    }

    btnUpdate.button('loading');

    HTTPRequest({
        url: apiUrl,
        success: function (responseJSON) {

            switch (type) {
                case "SOA":
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
            showPageLogin();
        }
    });

    return false;
}
