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
    loadServerList();

    //dropdown list box support
    $('.dropdown').on('click', 'a', function (e) {
        e.preventDefault();

        var itemText = $(this).text();
        $(this).closest('.dropdown').find('input').val(itemText);

        if (itemText.indexOf("QUIC") !== -1)
            $("#optDnsClientProtocol").val("QUIC");
        else if ((itemText.indexOf("TLS") !== -1) || (itemText.indexOf(":853") !== -1))
            $("#optDnsClientProtocol").val("TLS");
        else if ((itemText.indexOf("HTTPS") !== -1) || (itemText.indexOf("http://") !== -1) || (itemText.indexOf("https://") !== -1))
            $("#optDnsClientProtocol").val("HTTPS");
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
});

function loadServerList() {
    $.ajax({
        type: "GET",
        url: "json/dnsclient-server-list-custom.json",
        dataType: "json",
        cache: false,
        async: false,
        success: function (responseJSON, status, jqXHR) {
            loadServerListFrom(responseJSON);
        },
        error: function (jqXHR, textStatus, errorThrown) {
            $.ajax({
                type: "GET",
                url: "json/dnsclient-server-list-builtin.json",
                dataType: "json",
                cache: false,
                async: false,
                success: function (responseJSON, status, jqXHR) {
                    loadServerListFrom(responseJSON);
                },
                error: function (jqXHR, textStatus, errorThrown) {
                    showAlert("danger", "Error!", "Failed to load server list: " + jqXHR.status + " " + jqXHR.statusText);
                }
            });
        }
    });
}

function loadServerListFrom(responseJSON) {
    $("#txtDnsClientNameServer").val("This Server {this-server}");

    var htmlList = "<li><a href=\"#\">This Server {this-server}</a></li>";

    for (var i = 0; i < responseJSON.length; i++) {
        for (var j = 0; j < responseJSON[i].addresses.length; j++) {
            if ((responseJSON[i].name == null) || (responseJSON[i].name.length == 0))
                htmlList += "<li><a href=\"#\">" + htmlEncode(responseJSON[i].addresses[j]) + "</a></li>";
            else
                htmlList += "<li><a href=\"#\">" + htmlEncode(responseJSON[i].name) + " {" + htmlEncode(responseJSON[i].addresses[j]) + "}</a></li>";
        }
    }

    $("#optDnsClientNameServers").html(htmlList);
}

function resolveQuery(importRecords) {
    if (importRecords == null)
        importRecords = false;

    var server = $("#txtDnsClientNameServer").val();

    if ((server.indexOf("recursive-resolver") !== -1) || (server.indexOf("system-dns") !== -1))
        $("#optDnsClientProtocol").val("UDP");

    var domain = $("#txtDnsClientDomain").val();
    var type = $("#optDnsClientType").val();
    var protocol = $("#optDnsClientProtocol").val();
    var dnssecValidation = $("#chkDnsClientDnssecValidation").prop("checked");
    var eDnsClientSubnet = $("#txtDnsClientEDnsClientSubnet").val();

    {
        var i = server.indexOf("{");
        if (i > -1) {
            var j = server.lastIndexOf("}");
            server = server.substring(i + 1, j);
        }
    }

    server = server.trim();

    if ((server === null) || (server === "")) {
        showAlert("warning", "Missing!", "Please enter a valid Name Server.");
        $("#txtDnsClientNameServer").trigger("focus");
        return;
    }

    if ((domain === null) || (domain === "")) {
        showAlert("warning", "Missing!", "Please enter a domain name to query.");
        $("#txtDnsClientDomain").trigger("focus");
        return;
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
        if (!confirm("Importing all the records from the response of this query will add them into an existing primary or conditional forwarder zone. If a matching zone does not exists, a new primary zone for '" + domain + "' will be created.\n\nAre you sure you want to import all records?"))
            return;
    }

    var node = $("#optDnsClientClusterNode").val();

    var btn = $(importRecords ? "#btnDnsClientImport" : "#btnDnsClientResolve").button("loading");
    var btnOther = $(importRecords ? "#btnDnsClientResolve" : "#btnDnsClientImport").prop("disabled", true);

    var divDnsClientLoader = $("#divDnsClientLoader");
    var divDnsClientOutputAccordion = $("#divDnsClientOutputAccordion");

    divDnsClientOutputAccordion.hide();
    divDnsClientLoader.show();

    HTTPRequest({
        url: "api/dnsClient/resolve?token=" + sessionData.token + "&server=" + encodeURIComponent(server) + "&domain=" + encodeURIComponent(domain) + "&type=" + type + "&protocol=" + protocol + "&dnssec=" + dnssecValidation + "&eDnsClientSubnet=" + encodeURIComponent(eDnsClientSubnet) + (importRecords ? "&import=true" : "") + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            divDnsClientLoader.hide();
            btn.button("reset");
            btnOther.prop("disabled", false);

            $("#preDnsClientFinalResponse").text(JSON.stringify(responseJSON.response.result, null, 2));
            $("#divDnsClientFinalResponseCollapse").collapse("show");
            $("#divDnsClientRawResponsesCollapse").collapse("hide");
            divDnsClientOutputAccordion.show();

            if ((responseJSON.response.rawResponses != null)) {
                if (responseJSON.response.rawResponses.length == 0) {
                    $("#divDnsClientRawResponsePanel").hide();
                }
                else {
                    var rawListHtml = "";

                    for (var i = 0; i < responseJSON.response.rawResponses.length; i++) {
                        rawListHtml += "<li class=\"list-group-item\"><pre style=\"margin-top: 5px; margin-bottom: 5px;\">" + JSON.stringify(responseJSON.response.rawResponses[i], null, 2) + "</pre></li>";
                    }

                    $("#spanDnsClientRawResponsesCount").text(responseJSON.response.rawResponses.length);
                    $("#ulDnsClientRawResponsesList").html(rawListHtml);
                    $("#divDnsClientRawResponsesCollapse").collapse("hide");
                    $("#divDnsClientRawResponsePanel").show();
                }
            }

            if (responseJSON.response.warningMessage != null) {
                showAlert("warning", "Warning!", responseJSON.response.warningMessage);
            }
            else if (importRecords) {
                showAlert("success", "Records Imported!", "Resource records resolved by this DNS client query were successfully imported into this server.");
            }
        },
        error: function () {
            divDnsClientLoader.hide();
            btn.button("reset");
            btnOther.prop("disabled", false);
        },
        invalidToken: function () {
            divDnsClientLoader.hide();
            btn.button("reset");
            btnOther.prop("disabled", false);
            showPageLogin();
        },
        objLoaderPlaceholder: divDnsClientLoader,
        showInnerError: true
    });

    //add server name to list if doesnt exists
    var txtServerName = $("#txtDnsClientNameServer").val();
    var containsServer = false;

    $("#optDnsClientNameServers a").each(function () {
        if ($(this).html() === txtServerName)
            containsServer = true;
    });

    if (!containsServer)
        $("#optDnsClientNameServers").prepend("<li><a href=\"#\">" + htmlEncode(txtServerName) + "</a></li>");
}

function queryDnsServer(domain, type, node) {
    if (type == null)
        type = "A";

    $("#txtDnsClientNameServer").val("This Server {this-server}");
    $("#txtDnsClientDomain").val(domain);
    $("#optDnsClientType").val(type);
    $("#optDnsClientProtocol").val("UDP");
    $("#txtDnsClientEDnsClientSubnet").val("");
    $("#chkDnsClientDnssecValidation").prop("checked", false);

    if (node != null)
        $("#optDnsClientClusterNode").val(node);

    $("#mainPanelTabListDashboard").removeClass("active");
    $("#mainPanelTabPaneDashboard").removeClass("active");

    $("#mainPanelTabListLogs").removeClass("active");
    $("#mainPanelTabPaneLogs").removeClass("active");

    $("#mainPanelTabListDnsClient").addClass("active");
    $("#mainPanelTabPaneDnsClient").addClass("active");

    $("#modalTopStats").modal("hide");

    resolveQuery();
}
