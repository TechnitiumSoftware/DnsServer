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

                var detailsTable = "<table class=\"table\"><thead><th>Class Path</th><th>Description</th><th>Record Data Template</th></thead><tbody>";

                for (var j = 0; j < apps[i].details.length; j++) {
                    detailsTable += "<tr><td>" + htmlEncode(apps[i].details[j].classPath) + "</td><td>" +
                        htmlEncode(apps[i].details[j].description) + "</td><td>" +
                        (apps[i].details[j].recordDataTemplate == null ? "" : "<pre>" + htmlEncode(apps[i].details[j].recordDataTemplate) + "</pre>") + "</td></tr>";
                }

                if (apps[i].details.length == 0)
                    detailsTable += "<tr><td colspan=\"3\" align=\"center\">No Class Paths Found!</td></tr>";

                detailsTable += "</tbody></table>"

                tableHtmlRows += "<tr id=\"trApp" + id + "\"><td>" + htmlEncode(name) + "<br /><span class=\"label label-primary\">Version " + htmlEncode(version) + "</span></td>";
                tableHtmlRows += "<td>" + detailsTable + "</td>";
                tableHtmlRows += "<td><button type=\"button\" class=\"btn btn-default\" style=\"font-size: 12px; padding: 2px 0px; width: 80px; margin-bottom: 6px; display: block;\" onclick=\"showAppConfigModal(this, '" + name + "');\" data-loading-text=\"Loading...\">Config</button>";
                tableHtmlRows += "<button type=\"button\" class=\"btn btn-warning\" style=\"font-size: 12px; padding: 2px 0px; width: 80px; margin-bottom: 6px; display: block;\" onclick=\"showUpdateAppModal('" + name + "');\">Update</button>";
                tableHtmlRows += "<button type=\"button\" data-id=\"" + id + "\" class=\"btn btn-danger\" style=\"font-size: 12px; padding: 2px 0px; width: 80px; margin-bottom: 6px; display: block;\" onclick=\"uninstallApp(this, '" + name + "');\" data-loading-text=\"Uninstalling...\">Uninstall</button></td></tr>";
            }

            $("#tableAppsBody").html(tableHtmlRows);

            if (apps.length > 0)
                $("#tableAppsFooter").html("<tr><td colspan=\"5\"><b>Total Apps: " + apps.length + "</b></td></tr>");
            else
                $("#tableAppsFooter").html("<tr><td colspan=\"5\" align=\"center\">No Apps Found</td></tr>");

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
        url: "/api/apps/install?token=" + token + "&name=" + appName,
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
        url: "/api/apps/update?token=" + token + "&name=" + appName,
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
            showPageLogin();
        },
        objAlertPlaceholder: divUpdateAppAlert
    });
}

function uninstallApp(objBtn, appName) {
    if (!confirm("Are you sure you want to uninstall the DNS application '" + appName + "'?"))
        return false;

    var btn = $(objBtn);
    var id = btn.attr("data-id");

    btn.button('loading');

    HTTPRequest({
        url: "/api/apps/uninstall?token=" + token + "&name=" + appName,
        success: function (responseJSON) {
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
        url: "/api/apps/getConfig?token=" + token + "&name=" + appName,
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
        url: "/api/apps/setConfig?token=" + token + "&name=" + appName,
        data: "config=" + config,
        success: function (responseJSON) {
            $("#modalAppConfig").modal("hide");

            showAlert("success", "App Config Saved!", "The DNS application config was saved and reloaded successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            showPageLogin();
        },
        objAlertPlaceholder: divAppConfigAlert
    });
}