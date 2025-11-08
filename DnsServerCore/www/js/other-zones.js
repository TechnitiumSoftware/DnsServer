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

function flushDnsCache(objBtn, node) {
    if (!confirm("Are you sure to flush the DNS Server cache?"))
        return;

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/cache/flush?token=" + sessionData.token + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            $("#lstCachedZones").html("<div class=\"zone\"><a href=\"#\" onclick=\"refreshCachedZonesList(); return false;\"><b>[refresh]</b></a></div>");
            $("#txtCachedZoneViewerTitle").text("<ROOT>");
            $("#btnDeleteCachedZone").hide();
            $("#preCachedZoneViewerBody").hide();

            btn.button("reset");
            showAlert("success", "Flushed!", "DNS Server cache was flushed successfully.");
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

function deleteCachedZone() {
    var domain = $("#txtCachedZoneViewerTitle").text();

    if (!confirm("Are you sure you want to delete the cached zone '" + domain + "' and all its records?"))
        return;

    var node = $("#optCachedZonesClusterNode").val();

    var btn = $("#btnDeleteCachedZone");
    btn.button("loading");

    HTTPRequest({
        url: "api/cache/delete?token=" + sessionData.token + "&domain=" + encodeURIComponent(domain) + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            refreshCachedZonesList(getParentDomain(domain), "up");

            btn.button("reset");
            showAlert("success", "Deleted!", "Cached zone '" + domain + "' was deleted successfully.");
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
    if (domain == null) {
        domain = $("#txtCachedZoneViewerTitle").text();

        if ((domain == null) || (domain == "<ROOT>"))
            domain = "";
    }

    domain.toLowerCase();

    var node = $("#optCachedZonesClusterNode").val();

    var lstCachedZones = $("#lstCachedZones");
    var divCachedZoneViewer = $("#divCachedZoneViewer");
    var preCachedZoneViewerBody = $("#preCachedZoneViewerBody");

    divCachedZoneViewer.hide();
    preCachedZoneViewerBody.hide();

    HTTPRequest({
        url: "api/cache/list?token=" + sessionData.token + "&domain=" + encodeURIComponent(domain) + ((direction == null) ? "" : "&direction=" + direction) + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            var newDomain = responseJSON.response.domain;
            var zones = responseJSON.response.zones;

            var list = "<div class=\"zone\"><a href=\"#\" onclick=\"refreshCachedZonesList('" + newDomain + "'); return false;\"><b>[refresh]</b></a></div>";

            var parentDomain = getParentDomain(newDomain);

            if (parentDomain != null)
                list += "<div class=\"zone\"><a href=\"#\" onclick=\"refreshCachedZonesList('" + parentDomain + "', 'up'); return false;\"><b>[up]</b></a></div>";

            for (var i = 0; i < zones.length; i++) {
                var zoneName = htmlEncode(zones[i]);

                list += "<div class=\"zone\"><a href=\"#\" onclick=\"refreshCachedZonesList('" + zoneName + "'); return false;\">" + zoneName + "</a></div>";
            }

            lstCachedZones.html(list);

            if (newDomain == "") {
                $("#txtCachedZoneViewerTitle").text("<ROOT>");
                $("#btnDeleteCachedZone").hide();
            }
            else {
                if (responseJSON.response.domainIdn == null)
                    $("#txtCachedZoneViewerTitle").text(newDomain);
                else
                    $("#txtCachedZoneViewerTitle").text(responseJSON.response.domainIdn);

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
            lstCachedZones.html("<div class=\"zone\"><a href=\"#\" onclick=\"refreshCachedZonesList('" + domain + "'); return false;\"><b>[refresh]</b></a></div>");

            divCachedZoneViewer.show();
        },
        objLoaderPlaceholder: lstCachedZones
    });
}

function allowZone() {
    var domain = $("#txtAllowZone").val();

    if ((domain === null) || (domain === "")) {
        showAlert("warning", "Missing!", "Please enter a domain name to allow.");
        $("#txtAllowZone").trigger("focus");
        return;
    }

    var btn = $("#btnAllowZone");
    btn.button("loading");

    HTTPRequest({
        url: "api/allowed/add?token=" + sessionData.token + "&domain=" + encodeURIComponent(domain),
        success: function (responseJSON) {
            refreshAllowedZonesList(domain, null, true);

            $("#txtAllowZone").val("");
            btn.button("reset");

            showAlert("success", "Allowed!", "Domain '" + domain + "' was added to Allowed Zone successfully.");
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

function deleteAllowedZone() {
    var domain = $("#txtAllowedZoneViewerTitle").text();

    if (!confirm("Are you sure you want to delete the allowed zone '" + domain + "'?"))
        return;

    var btn = $("#btnDeleteAllowedZone");
    btn.button("loading");

    HTTPRequest({
        url: "api/allowed/delete?token=" + sessionData.token + "&domain=" + encodeURIComponent(domain),
        success: function (responseJSON) {
            refreshAllowedZonesList(getParentDomain(domain), "up", true);

            btn.button("reset");
            showAlert("success", "Deleted!", "Domain '" + domain + "' was deleted from Allowed Zone successfully.");
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

function flushAllowedZone() {
    if (!confirm("Are you sure you want to flush the entire Allowed zone?"))
        return;

    var btn = $("#btnFlushAllowedZone");
    btn.button("loading");

    HTTPRequest({
        url: "api/allowed/flush?token=" + sessionData.token,
        success: function (responseJSON) {
            $("#lstAllowedZones").html("<div class=\"zone\"><a href=\"#\" onclick=\"refreshAllowedZonesList(); return false;\"><b>[refresh]</b></a></div>");
            $("#txtAllowedZoneViewerTitle").text("<ROOT>");
            $("#btnDeleteAllowedZone").hide();
            $("#preAllowedZoneViewerBody").hide();

            btn.button("reset");
            showAlert("success", "Flushed!", "Allowed zone was flushed successfully.");
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

function refreshAllowedZonesList(domain, direction, fromPrimary) {
    if (domain == null) {
        domain = $("#txtAllowedZoneViewerTitle").text();

        if ((domain == null) || (domain == "<ROOT>"))
            domain = "";
    }

    domain.toLowerCase();

    var node = fromPrimary ? getPrimaryClusterNodeName() : "";

    var lstAllowedZones = $("#lstAllowedZones");
    var divAllowedZoneViewer = $("#divAllowedZoneViewer");
    var preAllowedZoneViewerBody = $("#preAllowedZoneViewerBody");

    divAllowedZoneViewer.hide();
    preAllowedZoneViewerBody.hide();

    HTTPRequest({
        url: "api/allowed/list?token=" + sessionData.token + "&domain=" + encodeURIComponent(domain) + ((direction == null) ? "" : "&direction=" + direction) + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            var newDomain = responseJSON.response.domain;
            var zones = responseJSON.response.zones;

            var list = "<div class=\"zone\"><a href=\"#\" onclick=\"refreshAllowedZonesList('" + newDomain + "'); return false;\"><b>[refresh]</b></a></div>";

            var parentDomain = getParentDomain(newDomain);

            if (parentDomain != null)
                list += "<div class=\"zone\"><a href=\"#\" onclick=\"refreshAllowedZonesList('" + parentDomain + "', 'up'); return false;\"><b>[up]</b></a></div>";

            for (var i = 0; i < zones.length; i++) {
                var zoneName = htmlEncode(zones[i]);

                list += "<div class=\"zone\"><a href=\"#\" onclick=\"refreshAllowedZonesList('" + zoneName + "'); return false;\">" + zoneName + "</a></div>";
            }

            lstAllowedZones.html(list);

            if (newDomain == "") {
                $("#txtAllowedZoneViewerTitle").text("<ROOT>");
            }
            else {
                if (responseJSON.response.domainIdn == null)
                    $("#txtAllowedZoneViewerTitle").text(newDomain);
                else
                    $("#txtAllowedZoneViewerTitle").text(responseJSON.response.domainIdn);
            }

            if (responseJSON.response.records.length > 0) {
                preAllowedZoneViewerBody.text(JSON.stringify(responseJSON.response.records, null, 2));
                preAllowedZoneViewerBody.show();

                $("#btnDeleteAllowedZone").show();
            }
            else {
                $("#btnDeleteAllowedZone").hide();
            }

            divAllowedZoneViewer.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        error: function () {
            lstAllowedZones.html("<div class=\"zone\"><a href=\"#\" onclick=\"refreshAllowedZonesList('" + domain + "'); return false;\"><b>[refresh]</b></a></div>");

            divAllowedZoneViewer.show();
        },
        objLoaderPlaceholder: lstAllowedZones
    });
}

function blockZone() {
    var domain = $("#txtBlockZone").val();

    if ((domain === null) || (domain === "")) {
        showAlert("warning", "Missing!", "Please enter a domain name to block.");
        $("#txtBlockZone").trigger("focus");
        return;
    }

    var btn = $("#btnBlockZone");
    btn.button("loading");

    HTTPRequest({
        url: "api/blocked/add?token=" + sessionData.token + "&domain=" + encodeURIComponent(domain),
        success: function (responseJSON) {
            refreshBlockedZonesList(domain, null, true);

            $("#txtBlockZone").val("");
            btn.button("reset");

            showAlert("success", "Blocked!", "Domain '" + domain + "' was added to Blocked Zone successfully.");
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

function deleteBlockedZone() {
    var domain = $("#txtBlockedZoneViewerTitle").text();

    if (!confirm("Are you sure you want to delete the blocked zone '" + domain + "'?"))
        return;

    var btn = $("#btnDeleteBlockedZone");
    btn.button("loading");

    HTTPRequest({
        url: "api/blocked/delete?token=" + sessionData.token + "&domain=" + encodeURIComponent(domain),
        success: function (responseJSON) {
            refreshBlockedZonesList(getParentDomain(domain), "up", true);

            btn.button("reset");
            showAlert("success", "Deleted!", "Blocked zone '" + domain + "' was deleted successfully.");
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

function flushBlockedZone() {
    if (!confirm("Are you sure you want to flush the entire Blocked zone?"))
        return;

    var btn = $("#btnFlushBlockedZone");
    btn.button("loading");

    HTTPRequest({
        url: "api/blocked/flush?token=" + sessionData.token,
        success: function (responseJSON) {
            $("#lstBlockedZones").html("<div class=\"zone\"><a href=\"#\" onclick=\"refreshBlockedZonesList(); return false;\"><b>[refresh]</b></a></div>");
            $("#txtBlockedZoneViewerTitle").text("<ROOT>");
            $("#btnDeleteBlockedZone").hide();
            $("#preBlockedZoneViewerBody").hide();

            btn.button("reset");
            showAlert("success", "Flushed!", "Blocked zone was flushed successfully.");
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

function refreshBlockedZonesList(domain, direction, fromPrimary) {
    if (domain == null) {
        domain = $("#txtBlockedZoneViewerTitle").text();

        if ((domain == null) || (domain == "<ROOT>"))
            domain = "";
    }

    domain.toLowerCase();

    var node = fromPrimary ? getPrimaryClusterNodeName() : "";

    var lstBlockedZones = $("#lstBlockedZones");
    var divBlockedZoneViewer = $("#divBlockedZoneViewer");
    var preBlockedZoneViewerBody = $("#preBlockedZoneViewerBody");

    divBlockedZoneViewer.hide();
    preBlockedZoneViewerBody.hide();

    HTTPRequest({
        url: "api/blocked/list?token=" + sessionData.token + "&domain=" + encodeURIComponent(domain) + ((direction == null) ? "" : "&direction=" + direction) + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            var newDomain = responseJSON.response.domain;
            var zones = responseJSON.response.zones;

            var list = "<div class=\"zone\"><a href=\"#\" onclick=\"refreshBlockedZonesList('" + newDomain + "'); return false;\"><b>[refresh]</b></a></div>";

            var parentDomain = getParentDomain(newDomain);

            if (parentDomain != null)
                list += "<div class=\"zone\"><a href=\"#\" onclick=\"refreshBlockedZonesList('" + parentDomain + "', 'up'); return false;\"><b>[up]</b></a></div>";

            for (var i = 0; i < zones.length; i++) {
                var zoneName = htmlEncode(zones[i]);

                list += "<div class=\"zone\"><a href=\"#\" onclick=\"refreshBlockedZonesList('" + zoneName + "'); return false;\">" + zoneName + "</a></div>";
            }

            lstBlockedZones.html(list);

            if (newDomain == "") {
                $("#txtBlockedZoneViewerTitle").text("<ROOT>");
            }
            else {
                if (responseJSON.response.domainIdn == null)
                    $("#txtBlockedZoneViewerTitle").text(newDomain);
                else
                    $("#txtBlockedZoneViewerTitle").text(responseJSON.response.domainIdn);
            }

            if (responseJSON.response.records.length > 0) {
                preBlockedZoneViewerBody.text(JSON.stringify(responseJSON.response.records, null, 2));
                preBlockedZoneViewerBody.show();

                $("#btnDeleteBlockedZone").show();
            }
            else {
                $("#btnDeleteBlockedZone").hide();
            }

            divBlockedZoneViewer.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        error: function () {
            lstBlockedZones.html("<div class=\"zone\"><a href=\"#\" onclick=\"refreshBlockedZonesList('" + domain + "'); return false;\"><b>[refresh]</b></a></div>");

            divBlockedZoneViewer.show();
        },
        objLoaderPlaceholder: lstBlockedZones
    });
}

function resetImportAllowedZonesModal() {
    $("#divImportAllowedZonesAlert").html("");
    $("#txtImportAllowedZones").val("");

    setTimeout(function () {
        $("#txtImportAllowedZones").trigger("focus");
    }, 1000);
}

function importAllowedZones() {
    var divImportAllowedZonesAlert = $("#divImportAllowedZonesAlert");
    var allowedZones = cleanTextList($("#txtImportAllowedZones").val());

    if ((allowedZones.length === 0) || (allowedZones === ",")) {
        showAlert("warning", "Missing!", "Please enter allowed zones to import.", divImportAllowedZonesAlert);
        $("#txtImportAllowedZones").trigger("focus");
        return;
    }

    var btn = $("#btnImportAllowedZones");
    btn.button("loading");

    HTTPRequest({
        url: "api/allowed/import?token=" + sessionData.token,
        method: "POST",
        data: "allowedZones=" + encodeURIComponent(allowedZones),
        processData: false,
        success: function (responseJSON) {
            $("#modalImportAllowedZones").modal("hide");
            btn.button("reset");

            showAlert("success", "Imported!", "Domain names were imported into allowed zone successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        },
        objAlertPlaceholder: divImportAllowedZonesAlert
    });
}

function exportAllowedZones() {
    window.open("api/allowed/export?token=" + sessionData.token, "_blank");

    showAlert("success", "Exported!", "Allowed zones were exported successfully.");
}

function resetImportBlockedZonesModal() {
    $("#divImportBlockedZonesAlert").html("");
    $("#txtImportBlockedZones").val("");

    setTimeout(function () {
        $("#txtImportBlockedZones").trigger("focus");
    }, 1000);
}

function importBlockedZones() {
    var divImportBlockedZonesAlert = $("#divImportBlockedZonesAlert");
    var blockedZones = cleanTextList($("#txtImportBlockedZones").val());

    if ((blockedZones.length === 0) || (blockedZones === ",")) {
        showAlert("warning", "Missing!", "Please enter blocked zones to import.", divImportBlockedZonesAlert);
        $("#txtImportBlockedZones").trigger("focus");
        return;
    }

    var btn = $("#btnImportBlockedZones");
    btn.button("loading");

    HTTPRequest({
        url: "api/blocked/import?token=" + sessionData.token,
        method: "POST",
        data: "blockedZones=" + encodeURIComponent(blockedZones),
        processData: false,
        success: function (responseJSON) {
            $("#modalImportBlockedZones").modal("hide");
            btn.button("reset");

            showAlert("success", "Imported!", "Domain names were imported into blocked zone successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        },
        objAlertPlaceholder: divImportBlockedZonesAlert
    });
}

function exportBlockedZones() {
    window.open("api/blocked/export?token=" + sessionData.token, "_blank");

    showAlert("success", "Exported!", "Blocked zones were exported successfully.");
}

function allowDomain(objMenuItem, btnName, alertPlaceholderName) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var domain = mnuItem.attr("data-domain");

    var btn = $("#" + btnName + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<img src='/img/loader-small.gif'/>");

    var alertPlaceholder;
    if (alertPlaceholderName != null)
        alertPlaceholder = $("#" + alertPlaceholderName);

    HTTPRequest({
        url: "api/blocked/delete?token=" + sessionData.token + "&domain=" + encodeURIComponent(domain),
        success: function (responseJSON) {
            HTTPRequest({
                url: "api/allowed/add?token=" + sessionData.token + "&domain=" + encodeURIComponent(domain),
                success: function (responseJSON) {
                    btn.prop("disabled", false);
                    btn.html(originalBtnHtml);

                    showAlert("success", "Allowed!", "Domain '" + domain + "' was added to Allowed Zone successfully.", alertPlaceholder);
                },
                error: function () {
                    btn.prop("disabled", false);
                    btn.html(originalBtnHtml);
                },
                invalidToken: function () {
                    showPageLogin();
                },
                objAlertPlaceholder: alertPlaceholder
            });
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            showPageLogin();
        },
        objAlertPlaceholder: alertPlaceholder
    });
}

function blockDomain(objMenuItem, btnName, alertPlaceholderName) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var domain = mnuItem.attr("data-domain");

    var btn = $("#" + btnName + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<img src='/img/loader-small.gif'/>");

    var alertPlaceholder;
    if (alertPlaceholderName != null)
        alertPlaceholder = $("#" + alertPlaceholderName);

    HTTPRequest({
        url: "api/allowed/delete?token=" + sessionData.token + "&domain=" + encodeURIComponent(domain),
        success: function (responseJSON) {
            HTTPRequest({
                url: "api/blocked/add?token=" + sessionData.token + "&domain=" + encodeURIComponent(domain),
                success: function (responseJSON) {
                    btn.prop("disabled", false);
                    btn.html(originalBtnHtml);

                    showAlert("success", "Blocked!", "Domain '" + domain + "' was added to Blocked Zone successfully.", alertPlaceholder);
                },
                error: function () {
                    btn.prop("disabled", false);
                    btn.html(originalBtnHtml);
                },
                invalidToken: function () {
                    showPageLogin();
                },
                objAlertPlaceholder: alertPlaceholder
            });
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            showPageLogin();
        },
        objAlertPlaceholder: alertPlaceholder
    });
}
