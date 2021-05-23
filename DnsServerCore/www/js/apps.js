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

function refreshApps() {
    var divViewAppsLoader = $("#divViewAppsLoader");
    var divViewApps = $("#divViewApps");

    divViewApps.hide();
    divViewAppsLoader.show();

    HTTPRequest({
        url: "/api/apps/list?token=" + token,
        success: function (responseJSON) {
            var apps = responseJSON.response.apps;
            var tableHtmlRows = "";

            for (var i = 0; i < apps.length; i++) {
                var id = Math.floor(Math.random() * 10000);
                var name = apps[i].name;
                var version = apps[i].version;
                var updateVersion = apps[i].updateVersion;
                var updateUrl = apps[i].updateUrl;
                var updateAvailable = apps[i].updateAvailable;

                var requestHandlersTable = "<table class=\"table\"><thead><th>Class Path</th><th>Description</th><th>Record Data Template</th></thead><tbody>";

                for (var j = 0; j < apps[i].requestHandlers.length; j++) {
                    requestHandlersTable += "<tr><td>" + htmlEncode(apps[i].requestHandlers[j].classPath) + "</td><td>" +
                        htmlEncode(apps[i].requestHandlers[j].description).replace(/\n/g, "<br />") + "</td><td>" +
                        (apps[i].requestHandlers[j].recordDataTemplate == null ? "" : "<pre>" + htmlEncode(apps[i].requestHandlers[j].recordDataTemplate) + "</pre>") + "</td></tr>";
                }

                if (apps[i].requestHandlers.length == 0)
                    requestHandlersTable += "<tr><td colspan=\"3\" align=\"center\">No Request Handlers Found!</td></tr>";

                requestHandlersTable += "</tbody></table>"

                tableHtmlRows += "<tr id=\"trApp" + id + "\"><td><div style=\"margin-bottom: 20px;\"><span style=\"font-weight: bold; font-size: 16px;\">" + htmlEncode(name) + "</span><br /><span id=\"trAppVersion" + id + "\" class=\"label label-primary\">Version " + htmlEncode(version) + "</span> <span id=\"trAppUpdateVersion" + id + "\" class=\"label label-warning\" style=\"" + (updateAvailable ? "" : "display: none;") + "\">Update " + htmlEncode(updateVersion) + "</span></div>";
                tableHtmlRows += "<div><div style=\"font-weight: bold; margin-bottom: 4px;\">APP Record Request Handlers</div>" + requestHandlersTable + "</div></td>";
                tableHtmlRows += "<td><button type=\"button\" class=\"btn btn-default\" style=\"font-size: 12px; padding: 2px 0px; width: 80px; margin-bottom: 6px; display: block;\" onclick=\"showAppConfigModal(this, '" + name + "');\" data-loading-text=\"Loading...\">Config</button>";
                tableHtmlRows += "<button type=\"button\" class=\"btn btn-warning\" style=\"font-size: 12px; padding: 2px 0px; width: 80px; margin-bottom: 6px; display: block;\" onclick=\"showUpdateAppModal('" + name + "');\">Update</button>";
                tableHtmlRows += "<button id=\"btnAppsStoreUpdate" + id + "\" type=\"button\" data-id=\"" + id + "\" class=\"btn btn-warning\" style=\"font-size: 12px; padding: 2px 0px; width: 80px; margin-bottom: 6px; " + (updateAvailable ? "" : "display: none;") + "\" onclick=\"updateStoreApp(this, '" + name + "', '" + updateUrl + "', false);\" data-loading-text=\"Updating...\">Store Update</button>";
                tableHtmlRows += "<button type=\"button\" data-id=\"" + id + "\" class=\"btn btn-danger\" style=\"font-size: 12px; padding: 2px 0px; width: 80px; margin-bottom: 6px; display: block;\" onclick=\"uninstallApp(this, '" + name + "');\" data-loading-text=\"Uninstalling...\">Uninstall</button></td></tr>";
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

function showStoreAppsModal() {
    var divStoreAppsAlert = $("#divStoreAppsAlert");
    var divStoreAppsLoader = $("#divStoreAppsLoader");
    var divStoreApps = $("#divStoreApps");

    divStoreAppsLoader.show();
    divStoreApps.hide();
    $("#modalStoreApps").modal("show");

    HTTPRequest({
        url: "/api/apps/listStoreApps?token=" + token,
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
        $("#txtInstallApp").focus();
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

    btn.button('loading');

    HTTPRequest({
        url: "/api/apps/downloadAndInstall?token=" + token + "&name=" + encodeURIComponent(appName) + "&url=" + encodeURIComponent(url),
        success: function (responseJSON) {
            btn.button('reset');
            btn.hide();

            var id = btn.attr("data-id");
            $("#btnStoreAppUninstall" + id).show();

            refreshApps();

            showAlert("success", "Store App Installed!", "DNS application was installed successfully from DNS App Store.", divStoreAppsAlert);
        },
        error: function () {
            btn.button('reset');
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

    btn.button('loading');

    HTTPRequest({
        url: "/api/apps/downloadAndUpdate?token=" + token + "&name=" + encodeURIComponent(appName) + "&url=" + encodeURIComponent(url),
        success: function (responseJSON) {
            btn.button('reset');
            btn.hide();

            var id = btn.attr("data-id");

            if (isModal) {
                $("#spanStoreAppUpdateVersion" + id).hide();
                $("#spanStoreAppDisplayVersion" + id).text($("#spanStoreAppUpdateVersion" + id).text().replace(/Update/g, "Version"));

                refreshApps();
            }
            else {
                $("#btnAppsStoreUpdate" + id).hide();
                $("#trAppUpdateVersion" + id).hide();
                $("#trAppVersion" + id).text($("#trAppUpdateVersion" + id).text().replace(/Update/g, "Version"));
            }

            showAlert("success", "Store App Updated!", "DNS application was updated successfully from DNS App Store.", divStoreAppsAlert);
        },
        error: function () {
            btn.button('reset');
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
        return false;

    var divStoreAppsAlert = $("#divStoreAppsAlert");
    var btn = $(objBtn);

    btn.button('loading');

    HTTPRequest({
        url: "/api/apps/uninstall?token=" + token + "&name=" + encodeURIComponent(appName),
        success: function (responseJSON) {
            btn.button('reset');
            btn.hide();

            var id = btn.attr("data-id");
            $("#btnStoreAppInstall" + id).show();
            $("#btnStoreAppUpdate" + id).hide();
            $("#spanStoreAppVersion" + id).attr("class", "label label-primary");

            refreshApps();

            showAlert("success", "Store App Uninstalled!", "DNS application was uninstalled successfully.", divStoreAppsAlert);
        },
        error: function () {
            btn.button('reset');
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
        $("#txtInstallApp").focus();
        return;
    }

    var fileAppZip = $("#fileAppZip");

    if (fileAppZip[0].files.length === 0) {
        showAlert("warning", "Missing!", "Please select an application zip file to install.", divInstallAppAlert);
        fileAppZip.focus();
        return false;
    }

    var formData = new FormData();
    formData.append("fileAppZip", $("#fileAppZip")[0].files[0]);

    var btn = $("#btnInstallApp").button('loading');

    HTTPRequest({
        url: "/api/apps/install?token=" + token + "&name=" + encodeURIComponent(appName),
        data: formData,
        dataIsFormData: true,
        success: function (responseJSON) {
            $("#modalInstallApp").modal("hide");

            refreshApps();

            showAlert("success", "App Installed!", "DNS application was installed successfully.");
        },
        error: function () {
            btn.button('reset');
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
        fileAppZip.focus();
        return false;
    }

    var formData = new FormData();
    formData.append("fileAppZip", $("#fileUpdateAppZip")[0].files[0]);

    var btn = $("#btnUpdateApp").button('loading');

    HTTPRequest({
        url: "/api/apps/update?token=" + token + "&name=" + encodeURIComponent(appName),
        data: formData,
        dataIsFormData: true,
        success: function (responseJSON) {
            $("#modalUpdateApp").modal("hide");

            refreshApps();

            showAlert("success", "App Updated!", "DNS application was updated successfully.");
        },
        error: function () {
            btn.button('reset');
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
        return false;

    var btn = $(objBtn);

    btn.button('loading');

    HTTPRequest({
        url: "/api/apps/uninstall?token=" + token + "&name=" + encodeURIComponent(appName),
        success: function (responseJSON) {
            var id = btn.attr("data-id");
            $("#trApp" + id).remove();

            var totalApps = $('#tableApps >tbody >tr').length;

            if (totalApps > 0)
                $("#tableAppsFooter").html("<tr><td colspan=\"3\"><b>Total Apps: " + totalApps + "</b></td></tr>");
            else
                $("#tableAppsFooter").html("<tr><td colspan=\"3\" align=\"center\">No App Found</td></tr>");

            showAlert("success", "App Uninstalled!", "DNS application was uninstalled successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function showAppConfigModal(objBtn, appName) {
    var btn = $(objBtn);

    btn.button('loading');

    HTTPRequest({
        url: "/api/apps/getConfig?token=" + token + "&name=" + encodeURIComponent(appName),
        success: function (responseJSON) {
            btn.button('reset');

            $("#divAppConfigAlert").html("");

            $("#lblAppConfigName").html(appName);
            $("#txtAppConfig").val(responseJSON.response.config);

            $("#btnAppConfig").button("reset");

            $("#modalAppConfig").modal("show");

            setTimeout(function () {
                $("#txtAppConfig").focus();
            }, 1000);
        },
        error: function () {
            btn.button('reset');
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

    var btn = $("#btnAppConfig").button("loading");

    HTTPRequest({
        url: "/api/apps/setConfig?token=" + token + "&name=" + encodeURIComponent(appName),
        data: "config=" + config,
        success: function (responseJSON) {
            $("#modalAppConfig").modal("hide");

            showAlert("success", "App Config Saved!", "The DNS application config was saved and reloaded successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            $("#modalAppConfig").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divAppConfigAlert
    });
}