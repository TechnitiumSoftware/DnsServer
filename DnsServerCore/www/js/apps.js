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

function refreshApps() {
    var divViewAppsLoader = $("#divViewAppsLoader");
    var divViewApps = $("#divViewApps");

    divViewApps.hide();
    divViewAppsLoader.show();

    HTTPRequest({
        url: "api/apps/list?token=" + sessionData.token,
        success: function (responseJSON) {
            var apps = responseJSON.response.apps;
            var tableHtmlRows = "";

            for (var i = 0; i < apps.length; i++) {
                tableHtmlRows += getAppRowHtml(apps[i]);
            }

            $("#tableAppsBody").html(tableHtmlRows);

            if (apps.length > 0)
                $("#tableAppsFooter").html("<tr><td colspan=\"3\"><b>Total Apps: " + apps.length + "</b></td></tr>");
            else
                $("#tableAppsFooter").html("<tr><td colspan=\"3\" align=\"center\">No Apps Found</td></tr>");

            divViewAppsLoader.hide();
            divViewApps.show();
        },
        error: function () {
            divViewAppsLoader.hide();
            divViewApps.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divViewAppsLoader
    });
}

function getAppRowId(appName) {
    return btoa(appName).replace(/=/g, "");
}

function getAppRowHtml(app) {
    var name = app.name;
    var version = app.version;
    var updateVersion = app.updateVersion;
    var updateUrl = app.updateUrl;
    var updateAvailable = app.updateAvailable;

    var dnsAppsTable = null;

    //dnsApps
    if (app.dnsApps.length > 0) {
        dnsAppsTable = "<table class=\"table\" style=\"margin-bottom: 10px; background: transparent;\"><thead><th>Class Path</th><th>Description</th></thead><tbody>";

        for (var j = 0; j < app.dnsApps.length; j++) {
            var labels = "";
            var description = null;

            if (app.dnsApps[j].isAppRecordRequestHandler) {
                labels += "<span class=\"label label-info\" style=\"margin-right: 4px;\">APP Record</span>";
                description = "<p>" + htmlEncode(app.dnsApps[j].description).replace(/\n/g, "<br />") + "</p>" + (app.dnsApps[j].recordDataTemplate == null ? "" : "<div><b>Record Data Template</b><pre>" + htmlEncode(app.dnsApps[j].recordDataTemplate) + "</pre></div>");
            }

            if (app.dnsApps[j].isRequestController)
                labels += "<span class=\"label label-info\" style=\"margin-right: 4px;\">Access Control</span>";

            if (app.dnsApps[j].isAuthoritativeRequestHandler)
                labels += "<span class=\"label label-info\" style=\"margin-right: 4px;\">Authoritative</span>";

            if (app.dnsApps[j].isRequestBlockingHandler)
                labels += "<span class=\"label label-info\" style=\"margin-right: 4px;\">Blocking</span>";

            if (app.dnsApps[j].isQueryLogger)
                labels += "<span class=\"label label-info\" style=\"margin-right: 4px;\">Query Logger</span>";

            if (app.dnsApps[j].isQueryLogs)
                labels += "<span class=\"label label-info\" style=\"margin-right: 4px;\">Query Logs</span>";

            if (app.dnsApps[j].isPostProcessor)
                labels += "<span class=\"label label-info\" style=\"margin-right: 4px;\">Post Processor</span>";

            if (labels == "")
                labels = "<span class=\"label label-info\" style=\"margin-right: 4px;\">Generic</span>";

            if (description == null)
                description = htmlEncode(app.dnsApps[j].description).replace(/\n/g, "<br />");

            dnsAppsTable += "<tr><td>" + htmlEncode(app.dnsApps[j].classPath) + "</br>" + labels + "</td><td>" + description + "</td></tr>";
        }

        dnsAppsTable += "</tbody></table>"
    }

    var id = getAppRowId(name);
    var tableHtmlRow = "<tr id=\"trApp" + id + "\"><td><div><span style=\"font-weight: bold; font-size: 16px;\">" + htmlEncode(name) + "</span><br /><span id=\"trAppVersion" + id + "\" class=\"label label-primary\">Version " + htmlEncode(version) + "</span> <span id=\"trAppUpdateVersion" + id + "\" class=\"label label-warning\" style=\"" + (updateAvailable ? "" : "display: none;") + "\">Update " + htmlEncode(updateVersion) + "</span></div>";

    if (app.description != null)
        tableHtmlRow += "<div style=\"margin-top: 10px;\">" + htmlEncode(app.description).replace(/\n/g, "<br />") + "</div>";

    if (dnsAppsTable != null) {
        tableHtmlRow += "<div style=\"margin-top: 10px;\"><a href=\"#" + id + "\" class=\"collapsed\" data-toggle=\"collapse\" aria-expanded=\"false\" aria-controls=\"" + id + "\">More Details <span class=\"glyphicon glyphicon-chevron-down\" style=\"font-size: 10px;\" aria-hidden=\"true\"></span></a>";
        tableHtmlRow += "<div id=\"" + id + "\" class=\"collapse\" aria-expanded=\"false\">";
        tableHtmlRow += dnsAppsTable;
        tableHtmlRow += "</div></div>";
    }

    tableHtmlRow += "</td>";
    tableHtmlRow += "<td><button type=\"button\" class=\"btn btn-default\" style=\"font-size: 12px; padding: 2px 0px; width: 80px; margin-bottom: 6px; display: block;\" onclick=\"showAppConfigModal(this, '" + name + "');\" data-loading-text=\"Loading...\">Config</button>";
    tableHtmlRow += "<button type=\"button\" class=\"btn btn-warning\" style=\"font-size: 12px; padding: 2px 0px; width: 80px; margin-bottom: 6px; display: block;\" onclick=\"showUpdateAppModal('" + name + "');\">Update</button>";
    tableHtmlRow += "<button id=\"btnAppsStoreUpdate" + id + "\" type=\"button\" data-id=\"" + id + "\" class=\"btn btn-warning\" style=\"font-size: 12px; padding: 2px 0px; width: 80px; margin-bottom: 6px; " + (updateAvailable ? "" : "display: none;") + "\" onclick=\"updateStoreApp(this, '" + name + "', '" + updateUrl + "', false);\" data-loading-text=\"Updating...\">Store Update</button>";
    tableHtmlRow += "<button type=\"button\" data-id=\"" + id + "\" class=\"btn btn-danger\" style=\"font-size: 12px; padding: 2px 0px; width: 80px; margin-bottom: 6px; display: block;\" onclick=\"uninstallApp(this, '" + name + "');\" data-loading-text=\"Uninstalling...\">Uninstall</button></td></tr>";

    return tableHtmlRow
}

function showStoreAppsModal() {
    var divStoreAppsAlert = $("#divStoreAppsAlert");
    var divStoreAppsLoader = $("#divStoreAppsLoader");
    var divStoreApps = $("#divStoreApps");

    divStoreAppsLoader.show();
    divStoreApps.hide();
    $("#modalStoreApps").modal("show");

    HTTPRequest({
        url: "api/apps/listStoreApps?token=" + sessionData.token,
        success: function (responseJSON) {
            var storeApps = responseJSON.response.storeApps;
            var tableHtmlRows = "";

            for (var i = 0; i < storeApps.length; i++) {
                var id = Math.floor(Math.random() * 10000);
                var name = storeApps[i].name;
                var version = storeApps[i].version;
                var description = storeApps[i].description;
                var url = storeApps[i].url;
                var size = storeApps[i].size;
                var installed = storeApps[i].installed;
                var installedVersion = storeApps[i].installedVersion;
                var updateAvailable = installed ? storeApps[i].updateAvailable : false;

                var displayVersion = installed ? installedVersion : version;
                description = htmlEncode(description).replace(/\n/g, "<br />");

                tableHtmlRows += "<tr id=\"trStoreApp" + id + "\"><td><div style=\"margin-bottom: 14px;\"><span style=\"font-weight: bold; font-size: 16px;\">" + htmlEncode(name) + "</span><br /><span id=\"spanStoreAppDisplayVersion" + id + "\" class=\"label label-primary\">Version " + htmlEncode(displayVersion) + "</span> <span id=\"spanStoreAppUpdateVersion" + id + "\" class=\"label label-warning\" style=\"" + (updateAvailable ? "" : "display: none;") + "\">Update " + htmlEncode(version) + "</span></div>";
                tableHtmlRows += "<div style=\"margin-bottom: 10px;\">" + description + "</div><div><b>App Zip File</b>: " + htmlEncode(url) + "<br /><b>Size</b>: " + htmlEncode(size) + "</div></td><td>";
                tableHtmlRows += "<button id=\"btnStoreAppInstall" + id + "\" type=\"button\" data-id=\"" + id + "\" class=\"btn btn-primary\" style=\"font-size: 12px; padding: 2px 0px; width: 80px; margin-bottom: 6px; " + (installed ? "display: none;" : "") + "\" onclick=\"installStoreApp(this, '" + name + "', '" + url + "');\" data-loading-text=\"Installing...\">Install</button>";
                tableHtmlRows += "<button id=\"btnStoreAppUpdate" + id + "\" type=\"button\" data-id=\"" + id + "\" class=\"btn btn-warning\" style=\"font-size: 12px; padding: 2px 0px; width: 80px; margin-bottom: 6px; " + (updateAvailable ? "" : "display: none;") + "\" onclick=\"updateStoreApp(this, '" + name + "', '" + url + "', true);\" data-loading-text=\"Updating...\">Update</button>";
                tableHtmlRows += "<button id=\"btnStoreAppUninstall" + id + "\" type=\"button\" data-id=\"" + id + "\" class=\"btn btn-danger\" style=\"font-size: 12px; padding: 2px 0px; width: 80px; margin-bottom: 6px; " + (installed ? "" : "display: none;") + "\" onclick=\"uninstallStoreApp(this, '" + name + "');\" data-loading-text=\"Uninstalling...\">Uninstall</button>";
                tableHtmlRows += "</td></tr>";
            }

            $("#tableStoreAppsBody").html(tableHtmlRows);

            if (storeApps.length > 0)
                $("#tableStoreAppsFooter").html("<tr><td colspan=\"3\"><b>Total Apps: " + storeApps.length + "</b></td></tr>");
            else
                $("#tableStoreAppsFooter").html("<tr><td colspan=\"3\" align=\"center\">No Apps Found</td></tr>");

            divStoreAppsLoader.hide();
            divStoreApps.show();
        },
        error: function () {
            divStoreAppsLoader.hide();
            divStoreApps.show();
        },
        invalidToken: function () {
            $("#modalStoreApps").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divStoreAppsAlert,
        objLoaderPlaceholder: divStoreAppsLoader
    });
}

function showInstallAppModal() {
    $("#divInstallAppAlert").html("");
    $("#txtInstallApp").val("");
    $("#fileAppZip").val("");
    $("#btnInstallApp").button("reset");

    $("#modalInstallApp").modal("show");

    setTimeout(function () {
        $("#txtInstallApp").trigger("focus");
    }, 1000);
}

function showUpdateAppModal(appName) {
    $("#divUpdateAppAlert").html("");
    $("#txtUpdateApp").val(appName);
    $("#fileUpdateAppZip").val("");
    $("#btnUpdateApp").button("reset");

    $("#modalUpdateApp").modal("show");
}

function installStoreApp(objBtn, appName, url) {
    var divStoreAppsAlert = $("#divStoreAppsAlert");

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/apps/downloadAndInstall?token=" + sessionData.token + "&name=" + encodeURIComponent(appName) + "&url=" + encodeURIComponent(url),
        success: function (responseJSON) {
            btn.button("reset");
            btn.hide();

            var id = btn.attr("data-id");
            $("#btnStoreAppUninstall" + id).show();

            var tableHtmlRow = getAppRowHtml(responseJSON.response.installedApp);
            $("#tableAppsBody").prepend(tableHtmlRow);
            updateAppsFooterCount();

            showAlert("success", "Store App Installed!", "DNS application '" + appName + "' was installed successfully from DNS App Store.", divStoreAppsAlert);
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalStoreApps").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divStoreAppsAlert
    });
}

function updateStoreApp(objBtn, appName, url, isModal) {
    var divStoreAppsAlert;

    if (isModal)
        divStoreAppsAlert = $("#divStoreAppsAlert");

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/apps/downloadAndUpdate?token=" + sessionData.token + "&name=" + encodeURIComponent(appName) + "&url=" + encodeURIComponent(url),
        success: function (responseJSON) {
            btn.button("reset");
            btn.hide();

            if (isModal) {
                var id = btn.attr("data-id");
                $("#spanStoreAppUpdateVersion" + id).hide();
                $("#spanStoreAppDisplayVersion" + id).text($("#spanStoreAppUpdateVersion" + id).text().replace(/Update/g, "Version"));
            }

            var tableHtmlRow = getAppRowHtml(responseJSON.response.updatedApp);
            var id = getAppRowId(responseJSON.response.updatedApp.name);
            $("#trApp" + id).replaceWith(tableHtmlRow);

            showAlert("success", "Store App Updated!", "DNS application '" + appName + "' was updated successfully from DNS App Store.", divStoreAppsAlert);
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalStoreApps").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divStoreAppsAlert
    });
}

function uninstallStoreApp(objBtn, appName) {
    if (!confirm("Are you sure you want to uninstall the DNS application '" + appName + "'?"))
        return;

    var divStoreAppsAlert = $("#divStoreAppsAlert");
    var btn = $(objBtn);

    btn.button("loading");

    HTTPRequest({
        url: "api/apps/uninstall?token=" + sessionData.token + "&name=" + encodeURIComponent(appName),
        success: function (responseJSON) {
            btn.button("reset");
            btn.hide();

            var id = btn.attr("data-id");
            $("#btnStoreAppInstall" + id).show();
            $("#btnStoreAppUpdate" + id).hide();
            $("#spanStoreAppVersion" + id).attr("class", "label label-primary");

            var id = getAppRowId(appName);
            $("#trApp" + id).remove();
            updateAppsFooterCount();

            showAlert("success", "Store App Uninstalled!", "DNS application '" + appName + "' was uninstalled successfully.", divStoreAppsAlert);
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalStoreApps").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divStoreAppsAlert
    });
}

function installApp() {
    var divInstallAppAlert = $("#divInstallAppAlert");
    var appName = $("#txtInstallApp").val();

    if ((appName === null) || (appName === "")) {
        showAlert("warning", "Missing!", "Please enter an application name.", divInstallAppAlert);
        $("#txtInstallApp").trigger("focus");
        return;
    }

    var fileAppZip = $("#fileAppZip");

    if (fileAppZip[0].files.length === 0) {
        showAlert("warning", "Missing!", "Please select an application zip file to install.", divInstallAppAlert);
        fileAppZip.trigger("focus");
        return;
    }

    var formData = new FormData();
    formData.append("fileAppZip", $("#fileAppZip")[0].files[0]);

    var btn = $("#btnInstallApp");
    btn.button("loading");

    HTTPRequest({
        url: "api/apps/install?token=" + sessionData.token + "&name=" + encodeURIComponent(appName),
        method: "POST",
        data: formData,
        contentType: false,
        processData: false,
        success: function (responseJSON) {
            $("#modalInstallApp").modal("hide");

            var tableHtmlRow = getAppRowHtml(responseJSON.response.installedApp);
            $("#tableAppsBody").prepend(tableHtmlRow);
            updateAppsFooterCount();

            showAlert("success", "App Installed!", "DNS application '" + appName + "' was installed successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalInstallApp").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divInstallAppAlert
    });
}

function updateApp() {
    var divUpdateAppAlert = $("#divUpdateAppAlert");
    var appName = $("#txtUpdateApp").val();
    var fileAppZip = $("#fileUpdateAppZip");

    if (fileAppZip[0].files.length === 0) {
        showAlert("warning", "Missing!", "Please select an application zip file to update.", divUpdateAppAlert);
        fileAppZip.trigger("focus");
        return;
    }

    var formData = new FormData();
    formData.append("fileAppZip", $("#fileUpdateAppZip")[0].files[0]);

    var btn = $("#btnUpdateApp");
    btn.button("loading");

    HTTPRequest({
        url: "api/apps/update?token=" + sessionData.token + "&name=" + encodeURIComponent(appName),
        method: "POST",
        data: formData,
        contentType: false,
        processData: false,
        success: function (responseJSON) {
            $("#modalUpdateApp").modal("hide");

            var tableHtmlRow = getAppRowHtml(responseJSON.response.updatedApp);
            var id = getAppRowId(responseJSON.response.updatedApp.name);
            $("#trApp" + id).replaceWith(tableHtmlRow);

            showAlert("success", "App Updated!", "DNS application '" + appName + "' was updated successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalUpdateApp").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divUpdateAppAlert
    });
}

function uninstallApp(objBtn, appName) {
    if (!confirm("Are you sure you want to uninstall the DNS application '" + appName + "'?"))
        return;

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/apps/uninstall?token=" + sessionData.token + "&name=" + encodeURIComponent(appName),
        success: function (responseJSON) {
            var id = btn.attr("data-id");
            $("#trApp" + id).remove();
            updateAppsFooterCount();

            showAlert("success", "App Uninstalled!", "DNS application '" + appName + "' was uninstalled successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function updateAppsFooterCount() {
    var totalApps = $("#tableApps >tbody >tr").length;
    if (totalApps > 0)
        $("#tableAppsFooter").html("<tr><td colspan=\"3\"><b>Total Apps: " + totalApps + "</b></td></tr>");
    else
        $("#tableAppsFooter").html("<tr><td colspan=\"3\" align=\"center\">No App Found</td></tr>");
}

function showAppConfigModal(objBtn, appName) {
    var node = getPrimaryClusterNodeName(); //always reading app config from primary node to avoid issues due to config propagation delays

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/apps/config/get?token=" + sessionData.token + "&name=" + encodeURIComponent(appName) + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            btn.button("reset");

            $("#divAppConfigAlert").html("");

            $("#lblAppConfigName").html(appName);
            $("#txtAppConfig").val(responseJSON.response.config);

            $("#btnAppConfig").button("reset");

            $("#modalAppConfig").modal("show");

            setTimeout(function () {
                $("#txtAppConfig").trigger("focus");
            }, 1000);
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function saveAppConfig() {
    var divAppConfigAlert = $("#divAppConfigAlert");

    var appName = $("#lblAppConfigName").text();
    var config = $("#txtAppConfig").val();

    var btn = $("#btnAppConfig");
    btn.button("loading");

    HTTPRequest({
        url: "api/apps/config/set?token=" + sessionData.token + "&name=" + encodeURIComponent(appName),
        method: "POST",
        data: "config=" + encodeURIComponent(config),
        processData: false,
        success: function (responseJSON) {
            $("#modalAppConfig").modal("hide");

            showAlert("success", "App Config Saved!", "The DNS application '" + appName + "' config was saved and reloaded successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalAppConfig").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divAppConfigAlert
    });
}
