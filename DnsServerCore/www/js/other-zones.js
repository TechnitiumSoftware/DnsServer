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

function flushDnsCache() {
    if (!confirm("Are you sure to flush the DNS Server cache?"))
        return;

    var btn = $("#btnFlushDnsCache").button('loading');

    HTTPRequest({
        url: "/api/flushDnsCache?token=" + token,
        success: function (responseJSON) {
            btn.button('reset');
            showAlert("success", "Cache Flushed!", "DNS Server cache was flushed successfully.");
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

function deleteCachedZone() {

    var domain = $("#txtCachedZoneViewerTitle").text();

    if (!confirm("Are you sure you want to delete the cached zone '" + domain + "' and all its records?"))
        return;

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

            var list = "<div class=\"zone\"><a href=\"#\" onclick=\"refreshCachedZonesList('" + newDomain + "'); return false;\"><b>[refresh]</b></a></div>"

            var parentDomain = getParentDomain(newDomain);

            if (parentDomain != null)
                list += "<div class=\"zone\"><a href=\"#\" onclick=\"refreshCachedZonesList('" + parentDomain + "', 'up'); return false;\"><b>[up]</b></a></div>"

            for (var i = 0; i < zones.length; i++) {
                var zoneName = htmlEncode(zones[i]);

                list += "<div class=\"zone\"><a href=\"#\" onclick=\"refreshCachedZonesList('" + zoneName + "'); return false;\">" + zoneName + "</a></div>"
            }

            lstCachedZones.html(list);

            if (newDomain == "") {
                $("#txtCachedZoneViewerTitle").text("<ROOT>");
                $("#btnDeleteCachedZone").hide();
            }
            else {
                $("#txtCachedZoneViewerTitle").text(newDomain);
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
        },
        objLoaderPlaceholder: lstCachedZones
    });
}

function allowZone() {
    var domain = $("#txtAllowZone").val();

    if ((domain === null) || (domain === "")) {
        showAlert("warning", "Missing!", "Please enter a domain name to allow.");
        $("#txtAllowZone").focus();
        return;
    }

    var btn = $("#btnAllowZone").button('loading');

    HTTPRequest({
        url: "/api/allowZone?token=" + token + "&domain=" + domain,
        success: function (responseJSON) {
            refreshAllowedZonesList(domain);

            $("#txtAllowZone").val("");
            btn.button('reset');

            showAlert("success", "Zone Allowed!", "Zone was allowed successfully.");
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

function deleteAllowedZone() {
    var domain = $("#txtAllowedZoneViewerTitle").text();

    if (!confirm("Are you sure you want to delete the allowed zone '" + domain + "'?"))
        return;

    var btn = $("#btnDeleteAllowedZone").button('loading');

    HTTPRequest({
        url: "/api/deleteAllowedZone?token=" + token + "&domain=" + domain,
        success: function (responseJSON) {
            refreshAllowedZonesList(getParentDomain(domain), "up");

            btn.button('reset');
            showAlert("success", "Allowed Zone Deleted!", "Allowed zone was deleted successfully.");
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

function refreshAllowedZonesList(domain, direction) {
    if (domain == null)
        domain = "";

    domain.toLowerCase();

    var lstAllowedZones = $("#lstAllowedZones");
    var divAllowedZoneViewer = $("#divAllowedZoneViewer");
    var preAllowedZoneViewerBody = $("#preAllowedZoneViewerBody");

    divAllowedZoneViewer.hide();
    preAllowedZoneViewerBody.hide();

    HTTPRequest({
        url: "/api/listAllowedZones?token=" + token + "&domain=" + domain + ((direction == null) ? "" : "&direction=" + direction),
        success: function (responseJSON) {
            var newDomain = responseJSON.response.domain;
            var zones = responseJSON.response.zones;

            var list = "<div class=\"zone\"><a href=\"#\" onclick=\"refreshAllowedZonesList('" + newDomain + "'); return false;\"><b>[refresh]</b></a></div>"

            var parentDomain = getParentDomain(newDomain);

            if (parentDomain != null)
                list += "<div class=\"zone\"><a href=\"#\" onclick=\"refreshAllowedZonesList('" + parentDomain + "', 'up'); return false;\"><b>[up]</b></a></div>"

            for (var i = 0; i < zones.length; i++) {
                var zoneName = htmlEncode(zones[i]);

                list += "<div class=\"zone\"><a href=\"#\" onclick=\"refreshAllowedZonesList('" + zoneName + "'); return false;\">" + zoneName + "</a></div>"
            }

            lstAllowedZones.html(list);

            if (newDomain == "") {
                $("#txtAllowedZoneViewerTitle").text("<ROOT>");
                $("#btnDeleteAllowedZone").hide();
            }
            else {
                $("#txtAllowedZoneViewerTitle").text(newDomain);
                $("#btnDeleteAllowedZone").show();
            }

            if (responseJSON.response.records.length > 0) {
                preAllowedZoneViewerBody.text(JSON.stringify(responseJSON.response.records, null, 2));
                preAllowedZoneViewerBody.show();
            }

            divAllowedZoneViewer.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        error: function () {
            lstAllowedZones.html("<div class=\"zone\"><a href=\"#\" onclick=\"refreshAllowedZonesList('" + domain + "'); return false;\"><b>[refresh]</b></a></div>");
        },
        objLoaderPlaceholder: lstAllowedZones
    });
}

function blockZone() {
    var domain = $("#txtBlockZone").val();

    if ((domain === null) || (domain === "")) {
        showAlert("warning", "Missing!", "Please enter a domain name to block.");
        $("#txtBlockZone").focus();
        return;
    }

    var btn = $("#btnBlockZone").button('loading');

    HTTPRequest({
        url: "/api/blockZone?token=" + token + "&domain=" + domain,
        success: function (responseJSON) {
            refreshBlockedZonesList(domain);

            $("#txtBlockZone").val("");
            btn.button('reset');

            showAlert("success", "Zone Blocked!", "Domain was added to Blocked Zone successfully.");
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

function deleteBlockedZone() {
    var domain = $("#txtBlockedZoneViewerTitle").text();

    if (!confirm("Are you sure you want to delete the blocked zone '" + domain + "'?"))
        return;

    var btn = $("#btnDeleteBlockedZone").button('loading');

    HTTPRequest({
        url: "/api/deleteBlockedZone?token=" + token + "&domain=" + domain,
        success: function (responseJSON) {
            refreshBlockedZonesList(getParentDomain(domain), "up");

            btn.button('reset');
            showAlert("success", "Blocked Zone Deleted!", "Blocked zone was deleted successfully.");
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

function refreshBlockedZonesList(domain, direction) {
    if (domain == null)
        domain = "";

    domain.toLowerCase();

    var lstBlockedZones = $("#lstBlockedZones");
    var divBlockedZoneViewer = $("#divBlockedZoneViewer");
    var preBlockedZoneViewerBody = $("#preBlockedZoneViewerBody");

    divBlockedZoneViewer.hide();
    preBlockedZoneViewerBody.hide();

    HTTPRequest({
        url: "/api/listBlockedZones?token=" + token + "&domain=" + domain + ((direction == null) ? "" : "&direction=" + direction),
        success: function (responseJSON) {
            var newDomain = responseJSON.response.domain;
            var zones = responseJSON.response.zones;

            var list = "<div class=\"zone\"><a href=\"#\" onclick=\"refreshBlockedZonesList('" + newDomain + "'); return false;\"><b>[refresh]</b></a></div>"

            var parentDomain = getParentDomain(newDomain);

            if (parentDomain != null)
                list += "<div class=\"zone\"><a href=\"#\" onclick=\"refreshBlockedZonesList('" + parentDomain + "', 'up'); return false;\"><b>[up]</b></a></div>"

            for (var i = 0; i < zones.length; i++) {
                var zoneName = htmlEncode(zones[i]);

                list += "<div class=\"zone\"><a href=\"#\" onclick=\"refreshBlockedZonesList('" + zoneName + "'); return false;\">" + zoneName + "</a></div>"
            }

            lstBlockedZones.html(list);

            if (newDomain == "") {
                $("#txtBlockedZoneViewerTitle").text("<ROOT>");
                $("#btnDeleteBlockedZone").hide();
            }
            else {
                $("#txtBlockedZoneViewerTitle").text(newDomain);
                $("#btnDeleteBlockedZone").show();
            }

            if (responseJSON.response.records.length > 0) {
                preBlockedZoneViewerBody.text(JSON.stringify(responseJSON.response.records, null, 2));
                preBlockedZoneViewerBody.show();
            }

            divBlockedZoneViewer.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        error: function () {
            lstBlockedZones.html("<div class=\"zone\"><a href=\"#\" onclick=\"refreshBlockedZonesList('" + domain + "'); return false;\"><b>[refresh]</b></a></div>");
        },
        objLoaderPlaceholder: lstBlockedZones
    });
}

function resetImportAllowedZonesModal() {
    $("#divImportAllowedZonesAlert").html("");
    $("#txtImportAllowedZones").val("");

    setTimeout(function () {
        $("#txtImportAllowedZones").focus();
    }, 1000);
}

function importAllowedZones() {
    var divImportAllowedZonesAlert = $("#divImportAllowedZonesAlert");
    var allowedZones = cleanTextList($("#txtImportAllowedZones").val());

    if ((allowedZones.length === 0) || (allowedZones === ",")) {
        showAlert("warning", "Missing!", "Please enter allowed zones to import.", divImportAllowedZonesAlert);
        $("#txtImportAllowedZones").focus();
        return;
    }

    var btn = $("#btnImportAllowedZones").button('loading');

    HTTPRequest({
        url: "/api/importAllowedZones?token=" + token,
        data: "allowedZones=" + allowedZones,
        success: function (responseJSON) {
            $("#modalImportAllowedZones").modal("hide");
            btn.button('reset');

            showAlert("success", "Imported!", "Domain names were imported to allowed zone successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
            showPageLogin();
        },
        objAlertPlaceholder: divImportAllowedZonesAlert
    });
}

function exportAllowedZones() {
    window.open("/api/exportAllowedZones?token=" + token, "_blank");

    showAlert("success", "Exported!", "Allowed zones were exported successfully.");
}

function resetImportBlockedZonesModal() {
    $("#divImportBlockedZonesAlert").html("");
    $("#txtImportBlockedZones").val("");

    setTimeout(function () {
        $("#txtImportBlockedZones").focus();
    }, 1000);
}

function importBlockedZones() {
    var divImportBlockedZonesAlert = $("#divImportBlockedZonesAlert");
    var blockedZones = cleanTextList($("#txtImportBlockedZones").val());

    if ((blockedZones.length === 0) || (blockedZones === ",")) {
        showAlert("warning", "Missing!", "Please enter blocked zones to import.", divImportBlockedZonesAlert);
        $("#txtImportBlockedZones").focus();
        return;
    }

    var btn = $("#btnImportBlockedZones").button('loading');

    HTTPRequest({
        url: "/api/importBlockedZones?token=" + token,
        data: "blockedZones=" + blockedZones,
        success: function (responseJSON) {
            $("#modalImportBlockedZones").modal("hide");
            btn.button('reset');

            showAlert("success", "Imported!", "Domain names were imported to blocked zone successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
            showPageLogin();
        },
        objAlertPlaceholder: divImportBlockedZonesAlert
    });
}

function exportBlockedZones() {
    window.open("/api/exportBlockedZones?token=" + token, "_blank");

    showAlert("success", "Exported!", "Blocked zones were exported successfully.");
}
