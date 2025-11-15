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

$(function () {
    $("#optQueryLogsAppName").on("change", function () {
        if (appsList == null)
            return;

        var appName = $("#optQueryLogsAppName").val();
        var optClassPaths = "";

        for (var i = 0; i < appsList.length; i++) {
            if (appsList[i].name == appName) {
                for (var j = 0; j < appsList[i].dnsApps.length; j++) {
                    if (appsList[i].dnsApps[j].isQueryLogs)
                        optClassPaths += "<option>" + appsList[i].dnsApps[j].classPath + "</option>";
                }

                break;
            }
        }

        $("#optQueryLogsClassPath").html(optClassPaths);
        $("#txtAddEditRecordDataData").val("");
    });

    $("#optQueryLogsEntriesPerPage").on("change", function () {
        localStorage.setItem("optQueryLogsEntriesPerPage", $("#optQueryLogsEntriesPerPage").val());
    });

    var optQueryLogsEntriesPerPage = localStorage.getItem("optQueryLogsEntriesPerPage");
    if (optQueryLogsEntriesPerPage != null)
        $("#optQueryLogsEntriesPerPage").val(optQueryLogsEntriesPerPage);
});

function refreshLogsTab() {
    if ($("#logsTabListLogViewer").hasClass("active"))
        refreshLogFilesList();
    else if ($("#logsTabListQueryLogs").hasClass("active"))
        refreshQueryLogsTab();
}

function logsClusterNodeChanged() {
    if ($("#logsTabListLogViewer").hasClass("active")) {
        if ($("#divLogViewer").is(":visible"))
            refreshLogFilesList($("#txtLogViewerTitle").text());
        else
            refreshLogFilesList();
    }
    else if ($("#logsTabListQueryLogs").hasClass("active")) {
        refreshQueryLogsTab();

        if ($("#divQueryLogsTable").is(":visible"))
            queryLogs();
    }
}

function refreshLogFilesList(selectedFileName) {
    var lstLogFiles = $("#lstLogFiles");

    var node = $("#optLogsClusterNode").val();

    HTTPRequest({
        url: "api/logs/list?token=" + sessionData.token + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            var logFiles = responseJSON.response.logFiles;

            var list = "<div class=\"log\" style=\"font-size: 14px; padding-bottom: 6px;\"><a href=\"#\" onclick=\"deleteAllStats(); return false;\"><b>[delete all stats]</b></a></div>";

            if (logFiles.length == 0) {
                list += "<div class=\"log\">No Log File Was Found</div>";
            }
            else {
                list += "<div class=\"log\" style=\"font-size: 14px; padding-bottom: 6px;\"><a href=\"#\" onclick=\"deleteAllLogs(); return false;\"><b>[delete all logs]</b></a></div>";

                for (var i = 0; i < logFiles.length; i++) {
                    var logFile = logFiles[i];

                    list += "<div class=\"log\"><a href=\"#\" onclick=\"viewLog('" + logFile.fileName + "'); return false;\">" + logFile.fileName + " [" + logFile.size + "]</a></div>"
                }
            }

            lstLogFiles.html(list);

            if (selectedFileName != null) {
                for (var i = 0; i < logFiles.length; i++) {
                    if (logFiles[i].fileName == selectedFileName) {
                        viewLog(selectedFileName);
                        return;
                    }
                }

                //selected file not found
                $("#divLogViewer").hide();
            }
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: lstLogFiles
    });
}

function viewLog(logFile) {
    var divLogViewer = $("#divLogViewer");
    var txtLogViewerTitle = $("#txtLogViewerTitle");
    var divLogViewerLoader = $("#divLogViewerLoader");
    var preLogViewerBody = $("#preLogViewerBody");

    txtLogViewerTitle.text(logFile);

    var node = $("#optLogsClusterNode").val();

    preLogViewerBody.hide();
    divLogViewerLoader.show();
    divLogViewer.show();

    HTTPRequest({
        url: "api/logs/download?token=" + sessionData.token + "&fileName=" + encodeURIComponent(logFile) + "&limit=2" + "&node=" + encodeURIComponent(node),
        isTextResponse: true,
        success: function (response) {
            divLogViewerLoader.hide();

            if (response.status != null)
                response = JSON.stringify(response, null, 2);

            preLogViewerBody.text(response);
            preLogViewerBody.show();
        },
        objLoaderPlaceholder: divLogViewerLoader
    });
}

function downloadLog() {
    var logFile = $("#txtLogViewerTitle").text();
    var node = $("#optLogsClusterNode").val();

    window.open("api/logs/download?token=" + sessionData.token + "&fileName=" + encodeURIComponent(logFile) + "&node=" + encodeURIComponent(node) + "&ts=" + (new Date().getTime()), "_blank");
}

function deleteLog() {
    var logFile = $("#txtLogViewerTitle").text();

    if (!confirm("Are you sure you want to permanently delete the log file '" + logFile + "'?"))
        return;

    var node = $("#optLogsClusterNode").val();

    var btn = $("#btnDeleteLog");
    btn.button("loading");

    HTTPRequest({
        url: "api/logs/delete?token=" + sessionData.token + "&log=" + encodeURIComponent(logFile) + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            refreshLogFilesList();

            $("#divLogViewer").hide();
            btn.button("reset");

            showAlert("success", "Log Deleted!", "Log file was deleted successfully.");
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

function deleteAllLogs() {
    if (!confirm("Are you sure you want to permanently delete all log files?"))
        return;

    var node = $("#optLogsClusterNode").val();

    HTTPRequest({
        url: "api/logs/deleteAll?token=" + sessionData.token + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            refreshLogFilesList();

            $("#divLogViewer").hide();

            showAlert("success", "Logs Deleted!", "All log files were deleted successfully.");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function deleteAllStats() {
    if (!confirm("Are you sure you want to permanently delete all stats files?"))
        return;

    var node = $("#optLogsClusterNode").val();

    HTTPRequest({
        url: "api/dashboard/stats/deleteAll?token=" + sessionData.token + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            showAlert("success", "Stats Deleted!", "All stats files were deleted successfully.");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

var appsList;

function refreshQueryLogsTab(doQueryLogs) {
    var frmQueryLogs = $("#frmQueryLogs");
    var divQueryLogsLoader = $("#divQueryLogsLoader");

    var optQueryLogsAppName = $("#optQueryLogsAppName");
    var optQueryLogsClassPath = $("#optQueryLogsClassPath");

    var currentAppName = optQueryLogsAppName.val();
    var currentClassPath = optQueryLogsClassPath.val();
    var loader;

    if (appsList == null) {
        frmQueryLogs.hide();
        loader = divQueryLogsLoader;
    }
    else {
        optQueryLogsAppName.prop("disabled", true);
        optQueryLogsClassPath.prop("disabled", true);
    }

    HTTPRequest({
        url: "api/apps/list?token=" + sessionData.token,
        success: function (responseJSON) {
            var apps = responseJSON.response.apps;

            var optApps = "";
            var optClassPaths = "";

            for (var i = 0; i < apps.length; i++) {
                for (var j = 0; j < apps[i].dnsApps.length; j++) {
                    if (apps[i].dnsApps[j].isQueryLogs) {
                        optApps += "<option>" + apps[i].name + "</option>";

                        if (currentAppName == null)
                            currentAppName = apps[i].name;

                        break;
                    }
                }
            }

            for (var i = 0; i < apps.length; i++) {
                if (apps[i].name == currentAppName) {
                    for (var j = 0; j < apps[i].dnsApps.length; j++) {
                        if (apps[i].dnsApps[j].isQueryLogs)
                            optClassPaths += "<option>" + apps[i].dnsApps[j].classPath + "</option>";
                    }

                    break;
                }
            }

            optQueryLogsAppName.html(optApps);
            optQueryLogsClassPath.html(optClassPaths);

            if (currentAppName != null)
                optQueryLogsAppName.val(currentAppName);

            if (currentClassPath != null)
                optQueryLogsClassPath.val(currentClassPath);

            if (appsList == null) {
                frmQueryLogs.show();
                loader.hide();
            }
            else {
                optQueryLogsAppName.prop("disabled", false);
                optQueryLogsClassPath.prop("disabled", false);
            }

            appsList = apps;

            if (doQueryLogs)
                queryLogs();
        },
        error: function () {
            if (appsList == null) {
                frmQueryLogs.show();
            }
            else {
                optQueryLogsAppName.prop("disabled", false);
                optQueryLogsClassPath.prop("disabled", false);
            }
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: loader
    });
}

function queryLogs(pageNumber) {
    var btn = $("#btnQueryLogs");
    var divQueryLogsLoader = $("#divQueryLogsLoader");
    var divQueryLogsTable = $("#divQueryLogsTable");

    var name = $("#optQueryLogsAppName").val();
    if (name == null) {
        showAlert("warning", "Missing!", "Please install the 'Query Logs (Sqlite)' DNS App or any other DNS app that supports query logging feature from the Apps section.");
        $("#optQueryLogsAppName").trigger("focus");
        return false;
    }

    var classPath = $("#optQueryLogsClassPath").val();
    if (classPath == null) {
        showAlert("warning", "Missing!", "Please select a Class Path to query logs.");
        $("#optQueryLogsClassPath").trigger("focus");
        return false;
    }

    if (pageNumber == null)
        pageNumber = $("#txtQueryLogPageNumber").val();

    var entriesPerPage = Number($("#optQueryLogsEntriesPerPage").val());
    if (entriesPerPage < 1)
        entriesPerPage = 10;

    var descendingOrder = $("#optQueryLogsDescendingOrder").val();

    var start = $("#txtQueryLogStart").val();
    if (start != "")
        start = moment(start).toISOString();

    var end = $("#txtQueryLogEnd").val();
    if (end != "")
        end = moment(end).toISOString();

    var clientIpAddress = $("#txtQueryLogClientIpAddress").val();
    var protocol = $("#optQueryLogsProtocol").val();
    var responseType = $("#optQueryLogsResponseType").val();
    var rcode = $("#optQueryLogsResponseCode").val();
    var qname = $("#txtQueryLogQName").val();
    var qtype = $("#txtQueryLogQType").val();
    var qclass = $("#optQueryLogQClass").val();

    var node = $("#optLogsClusterNode").val();

    divQueryLogsTable.hide();
    divQueryLogsLoader.show();

    btn.button("loading");

    HTTPRequest({
        url: "api/logs/query?token=" + sessionData.token + "&name=" + encodeURIComponent(name) + "&classPath=" + encodeURIComponent(classPath) + "&pageNumber=" + pageNumber + "&entriesPerPage=" + entriesPerPage + "&descendingOrder=" + descendingOrder +
            "&start=" + encodeURIComponent(start) + "&end=" + encodeURIComponent(end) + "&clientIpAddress=" + encodeURIComponent(clientIpAddress) + "&protocol=" + protocol + "&responseType=" + responseType + "&rcode=" + rcode +
            "&qname=" + encodeURIComponent(qname) + "&qtype=" + qtype + "&qclass=" + qclass +
            "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            var tableHtml = "";

            for (var i = 0; i < responseJSON.response.entries.length; i++) {
                var trbgcolor;

                switch (responseJSON.response.entries[i].rcode.toLowerCase()) {
                    case "serverfailure":
                        trbgcolor = "rgba(217, 83, 79, 0.1)";
                        break;

                    case "nxdomain":
                        switch (responseJSON.response.entries[i].responseType.toLowerCase()) {
                            case "blocked":
                            case "upstreamblocked":
                            case "upstreamblockedcached":
                                trbgcolor = "rgba(255, 165, 0, 0.1)";
                                break;

                            default:
                                trbgcolor = "rgba(120, 120, 120, 0.1)";
                                break;
                        }

                        break;

                    case "refused":
                        trbgcolor = "rgba(91, 192, 222, 0.1)";
                        break;

                    default:
                        switch (responseJSON.response.entries[i].responseType.toLowerCase()) {
                            case "authoritative":
                                trbgcolor = "rgba(150, 150, 0, 0.1)";
                                break;

                            case "recursive":
                                trbgcolor = "rgba(23, 162, 184, 0.1)";
                                break;

                            case "cached":
                                trbgcolor = "rgba(111, 84, 153, 0.1)";
                                break;

                            case "blocked":
                            case "upstreamblocked":
                            case "upstreamblockedcached":
                                trbgcolor = "rgba(255, 165, 0, 0.1)";
                                break;

                            default:
                                trbgcolor = null;
                                break;
                        }

                        break;
                }

                tableHtml += "<tr" + (trbgcolor == null ? "" : " style=\"background-color: " + trbgcolor + ";\"") + "><td>" + responseJSON.response.entries[i].rowNumber + "</td><td>" +
                    moment(responseJSON.response.entries[i].timestamp).local().format("YYYY-MM-DD HH:mm:ss") + "</td><td style=\"word-break: break-all; min-width: 125px;\">" +
                    responseJSON.response.entries[i].clientIpAddress + "</td><td>" +
                    responseJSON.response.entries[i].protocol + "</td><td>" +
                    responseJSON.response.entries[i].responseType + (responseJSON.response.entries[i].responseRtt == null ? "" : "<div style=\"font-size: 12px;\">(" + responseJSON.response.entries[i].responseRtt.toFixed(2) + " ms)</div>") + "</td><td>" +
                    responseJSON.response.entries[i].rcode + "</td><td style=\"word-break: break-all;\">" +
                    htmlEncode(responseJSON.response.entries[i].qname == "" ? "." : responseJSON.response.entries[i].qname) + "</td><td>" +
                    (responseJSON.response.entries[i].qtype == null ? "" : responseJSON.response.entries[i].qtype) + "</td><td>" +
                    (responseJSON.response.entries[i].qclass == null ? "" : responseJSON.response.entries[i].qclass) + "</td><td style=\"word-break: break-all;\">" +
                    htmlEncode(responseJSON.response.entries[i].answer) +
                    "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnQueryLogsRowOption" + i + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";

                tableHtml += "<li><a href=\"#\" data-id=\"" + i + "\" onclick=\"queryDnsServer('" + responseJSON.response.entries[i].qname + "', '" + responseJSON.response.entries[i].qtype + "'); return false;\">Query DNS Server</a></li>";

                switch (responseJSON.response.entries[i].responseType.toLowerCase()) {
                    case "blocked":
                    case "upstreamblocked":
                    case "upstreamblockedcached":
                        tableHtml += "<li><a href=\"#\" data-id=\"" + i + "\" data-domain=\"" + htmlEncode(responseJSON.response.entries[i].qname) + "\" onclick=\"allowDomain(this, 'btnQueryLogsRowOption'); return false;\">Allow Domain</a></li>";
                        break;

                    default:
                        tableHtml += "<li><a href=\"#\" data-id=\"" + i + "\" data-domain=\"" + htmlEncode(responseJSON.response.entries[i].qname) + "\" onclick=\"blockDomain(this, 'btnQueryLogsRowOption'); return false;\">Block Domain</a></li>";
                        break;
                }

                tableHtml += "</ul></div></td></tr>";
            }

            var paginationHtml = "";

            if (responseJSON.response.pageNumber > 1) {
                paginationHtml += "<li><a href=\"#\" aria-label=\"First\" onClick=\"queryLogs(1); return false;\"><span aria-hidden=\"true\">&laquo;</span></a></li>";
                paginationHtml += "<li><a href=\"#\" aria-label=\"Previous\" onClick=\"queryLogs(" + (responseJSON.response.pageNumber - 1) + "); return false;\"><span aria-hidden=\"true\">&lsaquo;</span></a></li>";
            }

            var pageStart = responseJSON.response.pageNumber - 5;
            if (pageStart < 1)
                pageStart = 1;

            var pageEnd = pageStart + 9;
            if (pageEnd > responseJSON.response.totalPages) {
                var endDiff = pageEnd - responseJSON.response.totalPages;
                pageEnd = responseJSON.response.totalPages;

                pageStart -= endDiff;
                if (pageStart < 1)
                    pageStart = 1;
            }

            for (var i = pageStart; i <= pageEnd; i++) {
                if (i == responseJSON.response.pageNumber)
                    paginationHtml += "<li class=\"active\"><a href=\"#\" onClick=\"queryLogs(" + i + "); return false;\">" + i + "</a></li>";
                else
                    paginationHtml += "<li><a href=\"#\" onClick=\"queryLogs(" + i + "); return false;\">" + i + "</a></li>";
            }

            if (responseJSON.response.pageNumber < responseJSON.response.totalPages) {
                paginationHtml += "<li><a href=\"#\" aria-label=\"Next\" onClick=\"queryLogs(" + (responseJSON.response.pageNumber + 1) + "); return false;\"><span aria-hidden=\"true\">&rsaquo;</span></a></li>";
                paginationHtml += "<li><a href=\"#\" aria-label=\"Last\" onClick=\"queryLogs(-1); return false;\"><span aria-hidden=\"true\">&raquo;</span></a></li>";
            }

            $("#tableQueryLogsBody").html(tableHtml);

            var statusHtml;

            if (responseJSON.response.entries.length > 0)
                statusHtml = responseJSON.response.entries[0].rowNumber + "-" + responseJSON.response.entries[responseJSON.response.entries.length - 1].rowNumber + " (" + responseJSON.response.entries.length + ") of " + responseJSON.response.totalEntries + " logs (page " + responseJSON.response.pageNumber + " of " + responseJSON.response.totalPages + ")";
            else
                statusHtml = "0 logs";

            $("#tableQueryLogsTopStatus").html(statusHtml);
            $("#tableQueryLogsTopPagination").html(paginationHtml);

            $("#tableQueryLogsFooterStatus").html(statusHtml);
            $("#tableQueryLogsFooterPagination").html(paginationHtml);

            btn.button("reset");
            divQueryLogsLoader.hide();
            divQueryLogsTable.show();
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        },
        objLoaderPlaceholder: divQueryLogsLoader
    });
}

function showQueryLogs(domain, clientIp) {
    $("#frmQueryLogs").trigger("reset");

    if (domain != null)
        $("#txtQueryLogQName").val(domain);

    if (clientIp != null)
        $("#txtQueryLogClientIpAddress").val(clientIp);

    $("#mainPanelTabListDashboard").removeClass("active");
    $("#mainPanelTabPaneDashboard").removeClass("active");

    $("#mainPanelTabListLogs").addClass("active");
    $("#mainPanelTabPaneLogs").addClass("active");

    $("#logsTabListLogViewer").removeClass("active");
    $("#logsTabPaneLogViewer").removeClass("active");

    $("#logsTabListQueryLogs").addClass("active");
    $("#logsTabPaneQueryLogs").addClass("active");

    $("#modalTopStats").modal("hide");

    refreshQueryLogsTab(true);
}

function exportQueryLogsCsv() {
    var name = $("#optQueryLogsAppName").val();
    if (name == null) {
        showAlert("warning", "Missing!", "Please install the 'Query Logs (Sqlite)' DNS App or any other DNS app that supports query logging feature.");
        $("#optQueryLogsAppName").trigger("focus");
        return false;
    }

    var classPath = $("#optQueryLogsClassPath").val();
    if (classPath == null) {
        showAlert("warning", "Missing!", "Please select a Class Path to query logs.");
        $("#optQueryLogsClassPath").trigger("focus");
        return false;
    }

    var start = $("#txtQueryLogStart").val();
    if (start != "")
        start = moment(start).toISOString();

    var end = $("#txtQueryLogEnd").val();
    if (end != "")
        end = moment(end).toISOString();

    var clientIpAddress = $("#txtQueryLogClientIpAddress").val();
    var protocol = $("#optQueryLogsProtocol").val();
    var responseType = $("#optQueryLogsResponseType").val();
    var rcode = $("#optQueryLogsResponseCode").val();
    var qname = $("#txtQueryLogQName").val();
    var qtype = $("#txtQueryLogQType").val();
    var qclass = $("#optQueryLogQClass").val();

    var node = $("#optLogsClusterNode").val();

    window.open("api/logs/export?token=" + sessionData.token + "&name=" + encodeURIComponent(name) + "&classPath=" + encodeURIComponent(classPath) +
        "&start=" + encodeURIComponent(start) + "&end=" + encodeURIComponent(end) + "&clientIpAddress=" + encodeURIComponent(clientIpAddress) +
        "&protocol=" + protocol + "&responseType=" + responseType + "&rcode=" + rcode + "&qname=" + encodeURIComponent(qname) + "&qtype=" + qtype + "&qclass=" + qclass +
        "&node=" + encodeURIComponent(node)
        , "_blank");
}
