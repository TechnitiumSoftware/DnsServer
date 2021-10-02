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

$(function () {
    $('#dtpQueryLogStart').datetimepicker({ format: "YYYY-MM-DD HH:mm:ss" });
    $('#dtpQueryLogEnd').datetimepicker({ format: "YYYY-MM-DD HH:mm:ss" });

    $("#optQueryLogsAppName").change(function () {
        if (appsList == null)
            return;

        var appName = $("#optQueryLogsAppName").val();
        var optClassPaths = "";

        for (var i = 0; i < appsList.length; i++) {
            if (appsList[i].name == appName) {
                for (var j = 0; j < appsList[i].dnsApps.length; j++) {
                    if (appsList[i].dnsApps[j].isQueryLogger)
                        optClassPaths += "<option>" + appsList[i].dnsApps[j].classPath + "</option>";
                }

                break;
            }
        }

        $("#optQueryLogsClassPath").html(optClassPaths);
        $("#txtAddEditRecordDataData").val("");
    });
});

function refreshLogsTab() {
    if ($("#logsTabListLogViewer").hasClass("active"))
        refreshLogFilesList();
    else if ($("#logsTabListQueryLogs").hasClass("active"))
        refreshQueryLogsTab();
}

function refreshLogFilesList() {
    var lstLogFiles = $("#lstLogFiles");

    HTTPRequest({
        url: "/api/listLogs?token=" + token,
        success: function (responseJSON) {
            var logFiles = responseJSON.response.logFiles;

            var list = "<div class=\"log\" style=\"font-size: 14px; padding-bottom: 6px;\"><a href=\"#\" onclick=\"deleteAllStats(); return false;\"><b>[delete all stats]</b></a></div>";

            if (logFiles.length == 0) {
                list += "<div class=\"log\">No Log Was Found</div>";
            }
            else {
                list += "<div class=\"log\" style=\"font-size: 14px; padding-bottom: 6px;\"><a href=\"#\" onclick=\"deleteAllLogs(); return false;\"><b>[delete all logs]</b></a></div>";

                for (var i = 0; i < logFiles.length; i++) {
                    var logFile = logFiles[i];

                    list += "<div class=\"log\"><a href=\"#\" onclick=\"viewLog('" + logFile.fileName + "'); return false;\">" + logFile.fileName + " [" + logFile.size + "]</a></div>"
                }
            }

            lstLogFiles.html(list);
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

    preLogViewerBody.hide();
    divLogViewerLoader.show();
    divLogViewer.show();

    HTTPGetFileRequest({
        url: "/log/" + logFile + "?limit=2&token=" + token,
        success: function (response) {

            divLogViewerLoader.hide();

            preLogViewerBody.text(response);
            preLogViewerBody.show();
        },
        objLoaderPlaceholder: divLogViewerLoader
    });
}

function downloadLog() {
    var logFile = $("#txtLogViewerTitle").text();
    window.open("/log/" + logFile + "?token=" + token + "&ts=" + (new Date().getTime()), "_blank");
}

function deleteLog() {
    var logFile = $("#txtLogViewerTitle").text();

    if (!confirm("Are you sure you want to permanently delete the log file '" + logFile + "'?"))
        return;

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
}

function deleteAllLogs() {
    if (!confirm("Are you sure you want to permanently delete all log files?"))
        return;

    HTTPRequest({
        url: "/api/deleteAllLogs?token=" + token,
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

    HTTPRequest({
        url: "/api/deleteAllStats?token=" + token,
        success: function (responseJSON) {
            showAlert("success", "Stats Deleted!", "All stats files were deleted successfully.");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

var appsList;

function refreshQueryLogsTab() {
    var frmQueryLogs = $("#frmQueryLogs");
    var divQueryLogsLoader = $("#divQueryLogsLoader");
    var divQueryLogsTable = $("#divQueryLogsTable");

    var optQueryLogsAppName = $("#optQueryLogsAppName");
    var optQueryLogsClassPath = $("#optQueryLogsClassPath");

    var currentAppName = optQueryLogsAppName.val();
    var currentClassPath = optQueryLogsClassPath.val();
    var loader;

    if (appsList == null) {
        frmQueryLogs.hide();
        divQueryLogsTable.hide();
        loader = divQueryLogsLoader;
    }
    else {
        optQueryLogsAppName.prop('disabled', true);
        optQueryLogsClassPath.prop('disabled', true);
    }

    HTTPRequest({
        url: "/api/apps/list?token=" + token,
        success: function (responseJSON) {
            var apps = responseJSON.response.apps;

            var optApps = "";
            var optClassPaths = "";

            for (var i = 0; i < apps.length; i++) {
                for (var j = 0; j < apps[i].dnsApps.length; j++) {
                    if (apps[i].dnsApps[j].isQueryLogger) {
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
                        if (apps[i].dnsApps[j].isQueryLogger)
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
                optQueryLogsAppName.prop('disabled', false);
                optQueryLogsClassPath.prop('disabled', false);
            }

            appsList = apps;
        },
        error: function () {
            if (appsList == null) {
                frmQueryLogs.show();
                divQueryLogsTable.show();
            }
            else {
                optQueryLogsAppName.prop('disabled', false);
                optQueryLogsClassPath.prop('disabled', false);
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
        showAlert("warning", "Missing!", "Please install a DNS App that supports query logging feature.");
        $("#optQueryLogsAppName").focus();
        return false;
    }

    var classPath = $("#optQueryLogsClassPath").val();
    if (classPath == null) {
        showAlert("warning", "Missing!", "Please select a Class Path to query logs.");
        $("#optQueryLogsClassPath").focus();
        return false;
    }

    if (pageNumber == null)
        pageNumber = $("#txtQueryLogPageNumber").val();

    var entriesPerPage = $("#optQueryLogsEntriesPerPage").val();
    var descendingOrder = $("#optQueryLogsDescendingOrder").val();

    var start = $("#txtQueryLogStart").val();
    if (start != "")
        start = moment(start).format("YYYY-MM-DD HH:mm:ss");

    var end = $("#txtQueryLogEnd").val();
    if (end != "")
        end = moment(end).format("YYYY-MM-DD HH:mm:ss");

    var clientIpAddress = $("#txtQueryLogClientIpAddress").val();
    var protocol = $("#optQueryLogsProtocol").val();
    var responseType = $("#optQueryLogsResponseType").val();
    var rcode = $("#optQueryLogsResponseCode").val();
    var qname = $("#txtQueryLogQName").val();
    var qtype = $("#txtQueryLogQType").val();
    var qclass = $("#optQueryLogQClass").val();

    divQueryLogsTable.hide();
    divQueryLogsLoader.show();

    btn.button('loading');

    HTTPRequest({
        url: "/api/queryLogs?token=" + token + "&name=" + encodeURIComponent(name) + "&classPath=" + encodeURIComponent(classPath) + "&pageNumber=" + pageNumber + "&entriesPerPage=" + entriesPerPage + "&descendingOrder=" + descendingOrder +
            "&start=" + encodeURIComponent(start) + "&end=" + encodeURIComponent(end) + "&clientIpAddress=" + encodeURIComponent(clientIpAddress) + "&protocol=" + protocol + "&responseType=" + responseType + "&rcode=" + rcode +
            "&qname=" + encodeURIComponent(qname) + "&qtype=" + qtype + "&qclass=" + qclass,
        success: function (responseJSON) {
            var tableHtml = "";

            for (var i = 0; i < responseJSON.response.entries.length; i++) {
                tableHtml += "<tr><td>" + responseJSON.response.entries[i].rowNumber + "</td><td>" +
                    moment(responseJSON.response.entries[i].timestamp).local().format("YYYY-MM-DD HH:mm:ss") + "</td><td>" +
                    responseJSON.response.entries[i].clientIpAddress + "</td><td>" +
                    responseJSON.response.entries[i].protocol + "</td><td>" +
                    responseJSON.response.entries[i].responseType + "</td><td>" +
                    responseJSON.response.entries[i].rcode + "</td><td style=\"word-break: break-all;\">" +
                    htmlEncode(responseJSON.response.entries[i].qname == "" ? "." : responseJSON.response.entries[i].qname) + "</td><td>" +
                    (responseJSON.response.entries[i].qtype == null ? "" : responseJSON.response.entries[i].qtype) + "</td><td>" +
                    (responseJSON.response.entries[i].qclass == null ? "" : responseJSON.response.entries[i].qclass) + "</td><td style=\"word-break: break-all;\">" +
                    htmlEncode(responseJSON.response.entries[i].answer) + "</td></tr>"
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

            btn.button('reset');
            divQueryLogsLoader.hide();
            divQueryLogsTable.show();
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divQueryLogsLoader
    });
}