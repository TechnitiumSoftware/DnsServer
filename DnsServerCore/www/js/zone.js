/*
Technitium DNS Server
Copyright (C) 2020  Shreyas Zare (shreyas@technitium.com)

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

    $("input[type=radio][name=rdAddZoneType]").change(function () {
        var zoneType = $('input[name=rdAddZoneType]:checked').val();
        switch (zoneType) {
            case "Primary":
                $("#divAddZonePrimaryNameServer").hide();
                $("#divAddZoneGlueAddresses").hide();
                $("#divAddZoneForwarderProtocol").hide();
                $("#divAddZoneForwarder").hide();
                break;

            case "Secondary":
            case "Stub":
                $("#divAddZonePrimaryNameServer").show();
                $("#divAddZoneGlueAddresses").show();
                $("#divAddZoneForwarderProtocol").hide();
                $("#divAddZoneForwarder").hide();
                break;

            case "Forwarder":
                $("#divAddZonePrimaryNameServer").hide();
                $("#divAddZoneGlueAddresses").hide();
                $("#divAddZoneForwarderProtocol").show();
                $("#divAddZoneForwarder").show();
                break;
        }
    });

    $("input[type=radio][name=rdAddZoneForwarderProtocol]").change(function () {
        var protocol = $('input[name=rdAddZoneForwarderProtocol]:checked').val();
        switch (protocol) {
            case "Udp":
            case "Tcp":
                $("#txtAddZoneForwarder").attr("placeholder", "8.8.8.8 or [2620:fe::10]")
                break;

            case "Tls":
                $("#txtAddZoneForwarder").attr("placeholder", "dns.quad9.net (9.9.9.9:853)")
                break;

            case "Https":
            case "HttpsJson":
                $("#txtAddZoneForwarder").attr("placeholder", "https://cloudflare-dns.com/dns-query (1.1.1.1)")
                break;
        }
    });

    $("input[type=radio][name=rdAddEditRecordDataForwarderProtocol]").change(updateAddEditFormForwarderPlaceholder);

});

function refreshZones(checkDisplay) {
    if (checkDisplay == null)
        checkDisplay = false;

    var divViewZones = $("#divViewZones");

    if (checkDisplay && (divViewZones.css('display') === "none"))
        return;

    var divViewZonesLoader = $("#divViewZonesLoader");
    var divEditZone = $("#divEditZone");

    divViewZones.hide();
    divEditZone.hide();
    divViewZonesLoader.show();

    HTTPRequest({
        url: "/api/listZones?token=" + token,
        success: function (responseJSON) {
            var zones = responseJSON.response.zones;
            var tableHtmlRows = "";

            for (var i = 0; i < zones.length; i++) {
                var id = Math.floor(Math.random() * 10000);
                var name = zones[i].name;

                if (name === "")
                    name = ".";

                var type;
                if (zones[i].internal)
                    type = "<span class=\"label label-default\">Internal</span>";
                else
                    type = "<span class=\"label label-primary\">" + zones[i].type + "</span>";

                var status;
                if (zones[i].disabled)
                    status = "<span id=\"tdStatus" + id + "\" class=\"label label-warning\">Disabled</span>";
                else if (zones[i].isExpired)
                    status = "<span id=\"tdStatus" + id + "\" class=\"label label-danger\">Expired</span>";
                else
                    status = "<span id=\"tdStatus" + id + "\" class=\"label label-success\">Enabled</span>";

                var expiry = zones[i].expiry;
                if (expiry == null)
                    expiry = "&nbsp;";

                var isReadOnlyZone = zones[i].internal || (zones[i].type === "Secondary");

                tableHtmlRows += "<tr id=\"trZone" + id + "\"><td>" + htmlEncode(name) + "</td>";
                tableHtmlRows += "<td>" + type + "</td>";
                tableHtmlRows += "<td>" + status + "</td>";
                tableHtmlRows += "<td>" + expiry + "</td>";
                tableHtmlRows += "<td align=\"right\" style=\"width: 220px;\"><button type=\"button\" class=\"btn btn-primary\" style=\"font-size: 12px; padding: 2px 0px; width: 60px; margin: 0 6px 6px 0;\" onclick=\"showEditZone('" + name + "');\">" + (isReadOnlyZone ? "View" : "Edit") + "</button>";
                tableHtmlRows += "<button type=\"button\" data-id=\"" + id + "\" id=\"btnEnableZone" + id + "\" class=\"btn btn-default\" style=\"font-size: 12px; padding: 2px 0px; width: 60px; margin: 0 6px 6px 0;" + (zones[i].disabled ? "" : " display: none;") + "\" onclick=\"enableZone(this, '" + name + "');\" data-loading-text=\"Enabling...\"" + (zones[i].internal ? " disabled" : "") + ">Enable</button>";
                tableHtmlRows += "<button type=\"button\" data-id=\"" + id + "\" id=\"btnDisableZone" + id + "\" class=\"btn btn-warning\" style=\"font-size: 12px; padding: 2px 0px; width: 60px; margin: 0 6px 6px 0;" + (!zones[i].disabled ? "" : " display: none;") + "\" onclick=\"disableZone(this, '" + name + "');\" data-loading-text=\"Disabling...\"" + (zones[i].internal ? " disabled" : "") + ">Disable</button>";
                tableHtmlRows += "<button type=\"button\" data-id=\"" + id + "\" class=\"btn btn-danger\" style=\"font-size: 12px; padding: 2px 0px; width: 60px; margin: 0 6px 6px 0;\" onclick=\"deleteZone(this, '" + name + "');\" data-loading-text=\"Deleting...\"" + (zones[i].internal ? " disabled" : "") + ">Delete</button></td></tr>";
            }

            $("#tableZonesBody").html(tableHtmlRows);

            if (zones.length > 0)
                $("#tableZonesFooter").html("<tr><td colspan=\"5\"><b>Total Zones: " + zones.length + "</b></td></tr>");
            else
                $("#tableZonesFooter").html("<tr><td colspan=\"5\" align=\"center\">No Zones Found</td></tr>");

            divViewZonesLoader.hide();
            divViewZones.show();
        },
        error: function () {
            divViewZonesLoader.hide();
            divViewZones.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divViewZonesLoader
    });
}

function enableZone(objBtn, domain) {
    var btn = $(objBtn);
    var id = btn.attr("data-id");

    btn.button('loading');

    HTTPRequest({
        url: "/api/enableZone?token=" + token + "&domain=" + domain,
        success: function (responseJSON) {
            btn.button('reset');

            $("#btnEnableZone" + id).hide();
            $("#btnDisableZone" + id).show();
            $("#tdStatus" + id).attr("class", "label label-success");
            $("#tdStatus" + id).html("Enabled");

            showAlert("success", "Zone Enabled!", "Zone '" + domain + "' was enabled successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function disableZone(objBtn, domain) {
    if (!confirm("Are you sure you want to disable the zone '" + domain + "'?"))
        return false;

    var btn = $(objBtn);
    var id = btn.attr("data-id");

    btn.button('loading');

    HTTPRequest({
        url: "/api/disableZone?token=" + token + "&domain=" + domain,
        success: function (responseJSON) {
            btn.button('reset');

            $("#btnEnableZone" + id).show();
            $("#btnDisableZone" + id).hide();
            $("#tdStatus" + id).attr("class", "label label-warning");
            $("#tdStatus" + id).html("Disabled");

            showAlert("success", "Zone Disabled!", "Zone '" + domain + "' was disabled successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function deleteZone(objBtn, domain, editZone) {
    if (!confirm("Are you sure you want to permanently delete the zone '" + domain + "' and all its records?"))
        return false;

    if (editZone == null)
        editZone = false;

    var btn = $(objBtn);
    var id = btn.attr("data-id");

    btn.button('loading');

    HTTPRequest({
        url: "/api/deleteZone?token=" + token + "&domain=" + domain,
        success: function (responseJSON) {
            if (editZone) {
                btn.button('reset');
                refreshZones();
            }
            else {
                $("#trZone" + id).remove();

                var totalZones = $('#tableZones >tbody >tr').length;

                if (totalZones > 0)
                    $("#tableZonesFooter").html("<tr><td colspan=\"5\"><b>Total Zones: " + totalZones + "</b></td></tr>");
                else
                    $("#tableZonesFooter").html("<tr><td colspan=\"5\" align=\"center\">No Zones Found</td></tr>");
            }

            showAlert("success", "Zone Deleted!", "Zone '" + domain + "' was deleted successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function showAddZoneModal() {
    $("#divAddZoneAlert").html("");

    $("#txtAddZone").val("");
    $("#rdAddZoneTypePrimary").prop("checked", true);
    $("#txtAddZonePrimaryNameServer").val("");
    $("#txtAddZoneGlueAddresses").val("");
    $("#rdAddZoneForwarderProtocolUdp").prop("checked", true);
    $("#txtAddZoneForwarder").attr("placeholder", "8.8.8.8 or [2620:fe::10]")
    $("#txtAddZoneForwarder").val("");

    $("#divAddZonePrimaryNameServer").hide();
    $("#divAddZoneGlueAddresses").hide();
    $("#divAddZoneForwarderProtocol").hide();
    $("#divAddZoneForwarder").hide();

    $("#btnAddZone").button('reset');

    $("#modalAddZone").modal("show");
}

function addZone() {
    var divAddZoneAlert = $("#divAddZoneAlert");
    var domain = $("#txtAddZone").val();

    if ((domain === null) || (domain === "")) {
        showAlert("warning", "Missing!", "Please enter a domain name to add zone.", divAddZoneAlert);
        $("#txtAddZone").focus();
        return;
    }

    var type = $('input[name=rdAddZoneType]:checked').val();

    var parameters;

    switch (type) {
        case "Secondary":
        case "Stub":
            parameters = "&primaryNameServer=" + $("#txtAddZonePrimaryNameServer").val() + "&glueAddresses=" + cleanTextList($("#txtAddZoneGlueAddresses").val());
            break;

        case "Forwarder":
            var forwarder = $("#txtAddZoneForwarder").val();

            if ((forwarder === null) || (forwarder === "")) {
                showAlert("warning", "Missing!", "Please enter a forwarder server name to add zone.", divAddZoneAlert);
                $("#divAddZoneForwarder").focus();
                return;
            }

            parameters = "&protocol=" + $('input[name=rdAddZoneForwarderProtocol]:checked').val() + "&forwarder=" + forwarder;
            break;

        default:
            parameters = "";
            break;
    }

    var btn = $("#btnAddZone").button('loading');

    HTTPRequest({
        url: "/api/createZone?token=" + token + "&domain=" + domain + "&type=" + type + parameters,
        success: function (responseJSON) {
            $("#modalAddZone").modal("hide");
            showEditZone(responseJSON.response.domain);

            showAlert("success", "Zone Added!", "Zone was added successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            showPageLogin();
        },
        objAlertPlaceholder: divAddZoneAlert
    });
}

function showEditZone(domain) {
    var divViewZonesLoader = $("#divViewZonesLoader");
    var divViewZones = $("#divViewZones");
    var divEditZone = $("#divEditZone");

    divViewZones.hide();
    divEditZone.hide();
    divViewZonesLoader.show();

    HTTPRequest({
        url: "/api/getRecords?token=" + token + "&domain=" + domain,
        success: function (responseJSON) {
            var type;
            if (responseJSON.response.zone.internal)
                type = "Internal";
            else
                type = responseJSON.response.zone.type;

            var status;
            if (responseJSON.response.zone.disabled)
                status = "Disabled";
            else if (responseJSON.response.zone.isExpired)
                status = "Expired";
            else
                status = "Enabled";

            var expiry = responseJSON.response.zone.expiry;
            if (expiry == null)
                expiry = "&nbsp;";
            else
                expiry = "Expiry: " + expiry;

            $("#titleEditZoneType").html(type);
            $("#tdStatusEditZone").html(status);
            $("#titleEditZoneExpiry").html(expiry);

            if (responseJSON.response.zone.internal)
                $("#titleEditZoneType").attr("class", "label label-default");
            else
                $("#titleEditZoneType").attr("class", "label label-primary");

            switch (status) {
                case "Disabled":
                    $("#tdStatusEditZone").attr("class", "label label-warning");
                    break;

                case "Expired":
                    $("#tdStatusEditZone").attr("class", "label label-danger");
                    break;

                case "Enabled":
                    $("#tdStatusEditZone").attr("class", "label label-success");
                    break;
            }

            switch (type) {
                case "Internal":
                case "Secondary":
                    $("#btnEditZoneAddRecord").hide();
                    break;

                case "Forwarder":
                    $("#btnEditZoneAddRecord").show();
                    $("#optEditRecordTypeFwd").show();
                    break;

                default:
                    $("#btnEditZoneAddRecord").show();
                    $("#optEditRecordTypeFwd").hide();
                    break;
            }

            if (responseJSON.response.zone.internal) {
                $("#btnEnableZoneEditZone").hide();
                $("#btnDisableZoneEditZone").hide();
                $("#btnEditZoneDeleteZone").hide();
            }
            else if (responseJSON.response.zone.disabled) {
                $("#btnEnableZoneEditZone").show();
                $("#btnDisableZoneEditZone").hide();
                $("#btnEditZoneDeleteZone").show();
            }
            else {
                $("#btnEnableZoneEditZone").hide();
                $("#btnDisableZoneEditZone").show();
                $("#btnEditZoneDeleteZone").show();
            }

            var records = responseJSON.response.records;
            var tableHtmlRows = "";

            for (var i = 0; i < records.length; i++) {
                var id = Math.floor(Math.random() * 10000);

                var name = records[i].name.toLowerCase();
                if (name === "")
                    name = ".";

                if (name === domain)
                    name = "@";
                else
                    name = name.replace("." + domain, "");

                tableHtmlRows += "<tr id=\"tr" + id + "\"><td>" + htmlEncode(name) + "</td>";
                tableHtmlRows += "<td>" + records[i].type + "</td>";
                tableHtmlRows += "<td>" + records[i].ttl + "</td>";

                var additionalDataAttributes = "";

                switch (records[i].type.toUpperCase()) {
                    case "A":
                    case "CNAME":
                    case "PTR":
                    case "TXT":
                    case "AAAA":
                    case "ANAME":
                        tableHtmlRows += "<td style=\"overflow-wrap: anywhere;\">" + htmlEncode(records[i].rData.value) + "</td>";
                        break;

                    case "NS":
                        tableHtmlRows += "<td style=\"overflow-wrap: anywhere;\"><b>Name Server:</b> " + htmlEncode(records[i].rData.value);

                        if (records[i].rData.glue != null) {
                            tableHtmlRows += "<br /><b>Glue Addresses:</b> " + records[i].rData.glue;

                            additionalDataAttributes = "data-record-glue=\"" + htmlEncode(records[i].rData.glue) + "\" ";
                        } else {
                            additionalDataAttributes = "data-record-glue=\"\" ";
                        }

                        tableHtmlRows += "</td>";
                        break;

                    case "SOA":
                        tableHtmlRows += "<td style=\"overflow-wrap: anywhere;\"><b>Primary Name Server:</b> " + htmlEncode(records[i].rData.primaryNameServer) +
                            "<br /><b>Responsible Person:</b> " + htmlEncode(records[i].rData.responsiblePerson) +
                            "<br /><b>Serial:</b> " + htmlEncode(records[i].rData.serial) +
                            "<br /><b>Refresh:</b> " + htmlEncode(records[i].rData.refresh) +
                            "<br /><b>Retry:</b> " + htmlEncode(records[i].rData.retry) +
                            "<br /><b>Expire:</b> " + htmlEncode(records[i].rData.expire) +
                            "<br /><b>Minimum:</b> " + htmlEncode(records[i].rData.minimum);

                        if (records[i].rData.glue != null) {
                            tableHtmlRows += "<br /><b>Glue Addresses:</b> " + records[i].rData.glue;

                            additionalDataAttributes = "data-record-glue=\"" + htmlEncode(records[i].rData.glue) + "\" ";
                        } else {
                            additionalDataAttributes = "data-record-glue=\"\" ";
                        }

                        tableHtmlRows += "</td>";

                        additionalDataAttributes += "data-record-mname=\"" + htmlEncode(records[i].rData.primaryNameServer) + "\" " +
                            "data-record-rperson=\"" + htmlEncode(records[i].rData.responsiblePerson) + "\" " +
                            "data-record-serial=\"" + htmlEncode(records[i].rData.serial) + "\" " +
                            "data-record-refresh=\"" + htmlEncode(records[i].rData.refresh) + "\" " +
                            "data-record-retry=\"" + htmlEncode(records[i].rData.retry) + "\" " +
                            "data-record-expire=\"" + htmlEncode(records[i].rData.expire) + "\" " +
                            "data-record-minimum=\"" + htmlEncode(records[i].rData.minimum) + "\" ";
                        break;

                    case "MX":
                        tableHtmlRows += "<td style=\"overflow-wrap: anywhere;\"><b>Preference: </b> " + htmlEncode(records[i].rData.preference) +
                            "<br /><b>Exchange:</b> " + htmlEncode(records[i].rData.value) + "</td>";

                        additionalDataAttributes = "data-record-preference=\"" + htmlEncode(records[i].rData.preference) + "\" ";
                        break;

                    case "SRV":
                        tableHtmlRows += "<td style=\"overflow-wrap: anywhere;\"><b>Priority: </b> " + htmlEncode(records[i].rData.priority) +
                            "<br /><b>Weight:</b> " + htmlEncode(records[i].rData.weight) +
                            "<br /><b>Port:</b> " + htmlEncode(records[i].rData.port) +
                            "<br /><b>Target:</b> " + htmlEncode(records[i].rData.value) + "</td>";

                        additionalDataAttributes = "data-record-priority=\"" + htmlEncode(records[i].rData.priority) + "\" " +
                            "data-record-weight=\"" + htmlEncode(records[i].rData.weight) + "\" " +
                            "data-record-port=\"" + htmlEncode(records[i].rData.port) + "\" ";
                        break;

                    case "CAA":
                        tableHtmlRows += "<td style=\"overflow-wrap: anywhere;\"><b>Flags: </b> " + htmlEncode(records[i].rData.flags) +
                            "<br /><b>Tag:</b> " + htmlEncode(records[i].rData.tag) +
                            "<br /><b>Authority:</b> " + htmlEncode(records[i].rData.value) + "</td>";

                        additionalDataAttributes = "data-record-flags=\"" + htmlEncode(records[i].rData.flags) + "\" " +
                            "data-record-tag=\"" + htmlEncode(records[i].rData.tag) + "\" ";
                        break;

                    case "FWD":
                        tableHtmlRows += "<td style=\"overflow-wrap: anywhere;\"><b>Protocol: </b> " + htmlEncode(records[i].rData.protocol) +
                            "<br /><b>Forwarder:</b> " + htmlEncode(records[i].rData.value) + "</td>";

                        additionalDataAttributes = "data-record-protocol=\"" + htmlEncode(records[i].rData.protocol) + "\" ";
                        break;

                    default:
                        tableHtmlRows += "<td style=\"overflow-wrap: anywhere;\"><b>RDATA:</b> " + htmlEncode(records[i].rData.value) + "</td>";
                        break;
                }

                var hideActionButtons = false;
                var disableEnableDisableDeleteButtons = false;

                switch (type) {
                    case "Internal":
                        hideActionButtons = true;
                        break;

                    case "Secondary":
                        switch (records[i].type) {
                            case "SOA":
                                disableEnableDisableDeleteButtons = true;
                                break;

                            default:
                                hideActionButtons = true;
                                break;
                        }
                        break;

                    case "Stub":
                        switch (records[i].type) {
                            case "SOA":
                                disableEnableDisableDeleteButtons = true;
                                break;

                            case "NS":
                                if (name == "@")
                                    hideActionButtons = true;

                                break;
                        }
                        break;

                    default:
                        switch (records[i].type) {
                            case "SOA":
                                disableEnableDisableDeleteButtons = true;
                                break;
                        }
                        break;
                }

                if (hideActionButtons) {
                    tableHtmlRows += "<td align=\"right\">&nbsp;</td>";
                }
                else {
                    tableHtmlRows += "<td align=\"right\" style=\"min-width: 220px;\">";
                    tableHtmlRows += "<div id=\"data" + id + "\" data-record-name=\"" + htmlEncode(records[i].name) + "\" data-record-type=\"" + records[i].type + "\" data-record-ttl=\"" + records[i].ttl + "\" data-record-value=\"" + htmlEncode(records[i].rData.value) + "\" " + additionalDataAttributes + " data-record-disabled=\"" + records[i].disabled + "\" style=\"display: none;\"></div>";
                    tableHtmlRows += "<button type=\"button\" class=\"btn btn-primary\" style=\"font-size: 12px; padding: 2px 0px; width: 60px; margin: 0 6px 6px 0;\" data-id=\"" + id + "\" onclick=\"showEditRecordModal(this);\">Edit</button>";
                    tableHtmlRows += "<button type=\"button\" class=\"btn btn-default\" id=\"btnEnableRecord" + id + "\" style=\"font-size: 12px; padding: 2px 0px; width: 60px; margin: 0 6px 6px 0;" + (records[i].disabled ? "" : " display: none;") + "\" data-id=\"" + id + "\" onclick=\"updateRecordState(this, false);\"" + (disableEnableDisableDeleteButtons ? " disabled" : "") + " data-loading-text=\"Enabling...\">Enable</button>";
                    tableHtmlRows += "<button type=\"button\" class=\"btn btn-warning\" id=\"btnDisableRecord" + id + "\" style=\"font-size: 12px; padding: 2px 0px; width: 60px; margin: 0 6px 6px 0;" + (!records[i].disabled ? "" : " display: none;") + "\" data-id=\"" + id + "\" onclick=\"updateRecordState(this, true);\"" + (disableEnableDisableDeleteButtons ? " disabled" : "") + " data-loading-text=\"Disabling...\">Disable</button>";
                    tableHtmlRows += "<button type=\"button\" class=\"btn btn-danger\" style=\"font-size: 12px; padding: 2px 0px; width: 60px; margin: 0 6px 6px 0;\" data-loading-text=\"Deleting...\" data-id=\"" + id + "\" onclick=\"deleteRecord(this);\"" + (disableEnableDisableDeleteButtons ? " disabled" : "") + ">Delete</button></td>";
                }

                tableHtmlRows += "</tr>";
            }

            $("#titleEditZone").text(domain);
            $("#tableEditZoneBody").html(tableHtmlRows);

            if (records.length > 0)
                $("#tableEditZoneFooter").html("<tr><td colspan=\"5\"><b>Total Records: " + records.length + "</b></td></tr>");
            else
                $("#tableEditZoneFooter").html("<tr><td colspan=\"5\" align=\"center\">No Records Found</td></tr>");

            divViewZonesLoader.hide();
            divEditZone.show();
        },
        error: function () {
            divViewZonesLoader.hide();
            divViewZones.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divViewZonesLoader
    });
}

function clearAddEditForm() {
    $("#divAddEditRecordAlert").html("");

    $("#txtAddEditRecordName").prop("disabled", false);
    $("#optAddEditRecordType").prop("disabled", false);
    $("#txtAddEditRecordTtl").prop("disabled", false);

    $("#txtAddEditRecordName").val("");
    $("#optAddEditRecordType").val("A");
    $("#txtAddEditRecordTtl").val("");

    $("#divAddEditRecordData").show();
    $("#lblAddEditRecordDataValue").text("IPv4 Address");
    $("#txtAddEditRecordDataValue").val("");
    $("#divAddEditRecordDataPtr").show();
    $("#chkAddEditRecordDataPtr").prop("checked", false);
    $("#chkAddEditRecordDataPtrLabel").text("Add reverse (PTR) record");

    $("#divAddEditRecordDataNs").hide();
    $("#txtAddEditRecordDataNsNameServer").prop("disabled", false);
    $("#txtAddEditRecordDataNsNameServer").val("");
    $("#txtAddEditRecordDataNsGlue").val("");

    $("#divEditRecordDataSoa").hide();
    $("#txtEditRecordDataSoaPrimaryNameServer").prop("disabled", false);
    $("#txtEditRecordDataSoaResponsiblePerson").prop("disabled", false);
    $("#txtEditRecordDataSoaSerial").prop("disabled", false);
    $("#txtEditRecordDataSoaRefresh").prop("disabled", false);
    $("#txtEditRecordDataSoaRetry").prop("disabled", false);
    $("#txtEditRecordDataSoaExpire").prop("disabled", false);
    $("#txtEditRecordDataSoaMinimum").prop("disabled", false);
    $("#txtEditRecordDataSoaPrimaryNameServer").val("");
    $("#txtEditRecordDataSoaResponsiblePerson").val("");
    $("#txtEditRecordDataSoaSerial").val("");
    $("#txtEditRecordDataSoaRefresh").val("");
    $("#txtEditRecordDataSoaRetry").val("");
    $("#txtEditRecordDataSoaExpire").val("");
    $("#txtEditRecordDataSoaMinimum").val("");

    $("#divAddEditRecordDataMx").hide();
    $("#txtAddEditRecordDataMxPreference").val("");
    $("#txtAddEditRecordDataMxExchange").val("");

    $("#divAddEditRecordDataSrv").hide();
    $("#txtAddEditRecordDataSrvPriority").val("");
    $("#txtAddEditRecordDataSrvWeight").val("");
    $("#txtAddEditRecordDataSrvPort").val("");
    $("#txtAddEditRecordDataSrvTarget").val("");

    $("#divAddEditRecordDataCaa").hide();
    $("#txtAddEditRecordDataCaaFlags").val("");
    $("#txtAddEditRecordDataCaaTag").val("");
    $("#txtAddEditRecordDataCaaValue").val("");

    $("#divAddEditRecordDataForwarder").hide();
    $("#rdAddEditRecordDataForwarderProtocolUdp").prop("checked", true);
    $("input[name=rdAddEditRecordDataForwarderProtocol]:radio").attr('disabled', false);
    $("#txtAddEditRecordDataForwarder").attr("placeholder", "8.8.8.8 or [2620:fe::10]")
    $("#txtAddEditRecordDataForwarder").val("");

    $("#btnAddEditRecord").button("reset");
}

function showAddRecordModal() {
    clearAddEditForm();

    $("#titleAddEditRecord").text("Add Record");
    $("#optEditRecordTypeSoa").hide();
    $("#btnAddEditRecord").attr("onclick", "addRecord(); return false;");

    $("#modalAddEditRecord").modal("show");
}

function modifyAddRecordForm() {
    $("#divAddEditRecordAlert").html("");

    $("#txtAddEditRecordName").prop("placeholder", "@");

    var type = $("#optAddEditRecordType").val();

    $("#divAddEditRecordData").hide();
    $("#divAddEditRecordDataPtr").hide();
    $("#divAddEditRecordDataNs").hide();
    $("#divEditRecordDataSoa").hide();
    $("#divAddEditRecordDataMx").hide();
    $("#divAddEditRecordDataSrv").hide();
    $("#divAddEditRecordDataCaa").hide();
    $("#divAddEditRecordDataForwarder").hide();

    switch (type) {
        case "A":
            $("#lblAddEditRecordDataValue").text("IPv4 Address");
            $("#txtAddEditRecordDataValue").val("");
            $("#chkAddEditRecordDataPtr").prop("checked", false);
            $("#chkAddEditRecordDataPtrLabel").text("Add reverse (PTR) record");
            $("#divAddEditRecordData").show();
            $("#divAddEditRecordDataPtr").show();
            break;

        case "AAAA":
            $("#lblAddEditRecordDataValue").text("IPv6 Address");
            $("#txtAddEditRecordDataValue").val("");
            $("#chkAddEditRecordDataPtr").prop("checked", false);
            $("#chkAddEditRecordDataPtrLabel").text("Add reverse (PTR) record");
            $("#divAddEditRecordData").show();
            $("#divAddEditRecordDataPtr").show();
            break;

        case "NS":
            $("#txtAddEditRecordDataNsNameServer").val("");
            $("#txtAddEditRecordDataNsGlue").val("");
            $("#divAddEditRecordDataNs").show();
            break;

        case "SOA":
            $("#txtEditRecordDataSoaPrimaryNameServer").val("");
            $("#txtEditRecordDataSoaResponsiblePerson").val("");
            $("#txtEditRecordDataSoaSerial").val("");
            $("#txtEditRecordDataSoaRefresh").val("");
            $("#txtEditRecordDataSoaRetry").val("");
            $("#txtEditRecordDataSoaExpire").val("");
            $("#txtEditRecordDataSoaMinimum").val("");
            $("#txtEditRecordDataSoaGlue").val("");
            $("#divEditRecordDataSoa").show();
            break;

        case "PTR":
        case "CNAME":
        case "ANAME":
            $("#lblAddEditRecordDataValue").text("Domain Name");
            $("#txtAddEditRecordDataValue").val("");
            $("#divAddEditRecordData").show();
            break;

        case "MX":
            $("#txtAddEditRecordDataMxPreference").val("");
            $("#txtAddEditRecordDataMxExchange").val("");
            $("#divAddEditRecordDataMx").show();
            break;

        case "TXT":
            $("#lblAddEditRecordDataValue").text("Text Data");
            $("#txtAddEditRecordDataValue").val("");
            $("#divAddEditRecordData").show();
            break;

        case "SRV":
            $("#txtAddEditRecordName").prop("placeholder", "_service._protocol.name");
            $("#txtAddEditRecordDataSrvPriority").val("");
            $("#txtAddEditRecordDataSrvWeight").val("");
            $("#txtAddEditRecordDataSrvPort").val("");
            $("#txtAddEditRecordDataSrvTarget").val("");
            $("#divAddEditRecordDataSrv").show();
            break;

        case "CAA":
            $("#txtAddEditRecordDataCaaFlags").val("");
            $("#txtAddEditRecordDataCaaTag").val("");
            $("#txtAddEditRecordDataCaaValue").val("");
            $("#divAddEditRecordDataCaa").show();
            break;

        case "FWD":
            $("#rdAddEditRecordDataForwarderProtocolUdp").prop("checked", true);
            $("#txtAddEditRecordDataForwarder").val("");
            $("#divAddEditRecordDataForwarder").show();
            break;
    }
}

function addRecord() {
    var btn = $("#btnAddEditRecord");
    var divAddEditRecordAlert = $("#divAddEditRecordAlert");

    var domain;
    {
        var subDomain = $("#txtAddEditRecordName").val();
        if (subDomain === "")
            subDomain = "@";

        var zone = $("#titleEditZone").text();

        if (subDomain === "@")
            domain = zone;
        else if (zone === ".")
            domain = subDomain + ".";
        else
            domain = subDomain + "." + zone;
    }

    var type = $("#optAddEditRecordType").val();

    var ttl = $("#txtAddEditRecordTtl").val();
    if (ttl === "")
        ttl = 3600;

    var apiUrl = "/api/addRecord?token=" + token + "&domain=" + encodeURIComponent(domain) + "&type=" + type + "&ttl=" + ttl;

    switch (type) {
        case "A":
        case "AAAA":
            var value = $("#txtAddEditRecordDataValue").val();
            if (value === "") {
                showAlert("warning", "Missing!", "Please enter an IP address to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").focus();
                return;
            }

            apiUrl += "&value=" + encodeURIComponent(value) + "&ptr=" + $("#chkAddEditRecordDataPtr").prop('checked');
            break;

        case "PTR":
        case "TXT":
        case "ANAME":
            var value = $("#txtAddEditRecordDataValue").val();
            if (value === "") {
                showAlert("warning", "Missing!", "Please enter a suitable value to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").focus();
                return;
            }

            apiUrl += "&value=" + encodeURIComponent(value);
            break;

        case "CNAME":
            var subDomainName = $("#txtAddEditRecordName").val();
            if ((subDomainName === "") || (subDomainName === "@")) {
                showAlert("warning", "Missing!", "Please enter a name for the CNAME record.", divAddEditRecordAlert);
                $("#txtAddEditRecordName").focus();
                return;
            }

            var value = $("#txtAddEditRecordDataValue").val();
            if (value === "") {
                showAlert("warning", "Missing!", "Please enter a domain name to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").focus();
                return;
            }

            apiUrl += "&value=" + encodeURIComponent(value);
            break;

        case "NS":
            var value = $("#txtAddEditRecordDataNsNameServer").val();
            if (value === "") {
                showAlert("warning", "Missing!", "Please enter a name server to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataNsNameServer").focus();
                return;
            }

            var glue = cleanTextList($("#txtAddEditRecordDataNsGlue").val());

            apiUrl += "&value=" + encodeURIComponent(value) + "&glue=" + encodeURIComponent(glue);
            break;

        case "MX":
            var preference = $("#txtAddEditRecordDataMxPreference").val();
            if (preference === "")
                preference = 1;

            var value = $("#txtAddEditRecordDataMxExchange").val();
            if (value === "") {
                showAlert("warning", "Missing!", "Please enter a mail exchange domain name to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataMxExchange").focus();
                return;
            }

            apiUrl += "&preference=" + preference + "&value=" + encodeURIComponent(value);
            break;

        case "SRV":
            if ($("#txtAddEditRecordName").val() === "") {
                showAlert("warning", "Missing!", "Please enter a name that includes service and protocol labels.", divAddEditRecordAlert);
                $("#txtAddEditRecordName").focus();
                return;
            }

            var priority = $("#txtAddEditRecordDataSrvPriority").val();
            if (priority === "") {
                showAlert("warning", "Missing!", "Please enter a suitable priority.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvPriority").focus();
                return;
            }

            var weight = $("#txtAddEditRecordDataSrvWeight").val();
            if (weight === "") {
                showAlert("warning", "Missing!", "Please enter a suitable weight.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvWeight").focus();
                return;
            }

            var port = $("#txtAddEditRecordDataSrvPort").val();
            if (port === "") {
                showAlert("warning", "Missing!", "Please enter a suitable port number.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvPort").focus();
                return;
            }

            var value = $("#txtAddEditRecordDataSrvTarget").val();
            if (value === "") {
                showAlert("warning", "Missing!", "Please enter a suitable value into the target field.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvTarget").focus();
                return;
            }

            apiUrl += "&priority=" + priority + "&weight=" + weight + "&port=" + port + "&value=" + encodeURIComponent(value);
            break;

        case "CAA":
            var flags = $("#txtAddEditRecordDataCaaFlags").val();
            if (flags === "")
                flags = 0;

            var tag = $("#txtAddEditRecordDataCaaTag").val();
            if (tag === "")
                tag = "issue";

            var value = $("#txtAddEditRecordDataCaaValue").val();
            if (value === "") {
                showAlert("warning", "Missing!", "Please enter a suitable value into the authority field.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataCaaValue").focus();
                return;
            }

            apiUrl += "&flags=" + flags + "&tag=" + encodeURIComponent(tag) + "&value=" + encodeURIComponent(value);
            break;

        case "FWD":
            var value = $("#txtAddEditRecordDataForwarder").val();
            if (value === "") {
                showAlert("warning", "Missing!", "Please enter a domain name or IP address or URL as a forwarder to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataForwarder").focus();
                return;
            }

            apiUrl += "&protocol=" + $('input[name=rdAddEditRecordDataForwarderProtocol]:checked').val() + "&value=" + value;
            break;
    }

    btn.button("loading");

    HTTPRequest({
        url: apiUrl,
        success: function (responseJSON) {
            $("#modalAddEditRecord").modal("hide");
            showEditZone(zone);
            showAlert("success", "Record Added!", "Resource record was added successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            showPageLogin();
        },
        objAlertPlaceholder: divAddEditRecordAlert
    });
}

function updateAddEditFormForwarderPlaceholder() {
    var protocol = $('input[name=rdAddEditRecordDataForwarderProtocol]:checked').val();
    switch (protocol) {
        case "Udp":
        case "Tcp":
            $("#txtAddEditRecordDataForwarder").attr("placeholder", "8.8.8.8 or [2620:fe::10]")
            break;

        case "Tls":
            $("#txtAddEditRecordDataForwarder").attr("placeholder", "dns.quad9.net (9.9.9.9:853)")
            break;

        case "Https":
        case "HttpsJson":
            $("#txtAddEditRecordDataForwarder").attr("placeholder", "https://cloudflare-dns.com/dns-query (1.1.1.1)")
            break;
    }
}

function showEditRecordModal(objBtn) {
    var btn = $(objBtn);
    var id = btn.attr("data-id");
    var divData = $("#data" + id);

    var zone = $("#titleEditZone").text();
    var name = divData.attr("data-record-name");
    var type = divData.attr("data-record-type");
    var ttl = divData.attr("data-record-ttl");

    if (name === zone)
        name = "@";
    else
        name = name.replace("." + zone, "");

    clearAddEditForm();
    $("#titleAddEditRecord").text("Edit Record");
    $("#optEditRecordTypeSoa").show();
    $("#optAddEditRecordType").val(type);
    modifyAddRecordForm();

    $("#txtAddEditRecordName").val(name);
    $("#txtAddEditRecordTtl").val(ttl)

    var disableEditRecordModalFields = false;
    var hideEditRecordGlueField = false;

    var zoneType = $("#titleEditZoneType").text();
    switch (zoneType) {
        case "Primary":
            switch (type) {
                case "SOA":
                    hideEditRecordGlueField = true;
                    break;
            }
            break;

        case "Secondary":
            switch (type) {
                case "SOA":
                    disableEditRecordModalFields = true;
                    break;
            }
            break;

        case "Stub":
            switch (type) {
                case "SOA":
                    disableEditRecordModalFields = true;
                    break;
            }
            break;
    }

    switch (type) {
        case "A":
        case "AAAA":
            $("#txtAddEditRecordDataValue").val(divData.attr("data-record-value"));
            $("#chkAddEditRecordDataPtr").prop("checked", false);
            $("#chkAddEditRecordDataPtrLabel").text("Update reverse (PTR) record");
            break;

        case "CNAME":
        case "PTR":
        case "TXT":
        case "ANAME":
            $("#txtAddEditRecordDataValue").val(divData.attr("data-record-value"));
            break;

        case "NS":
            $("#txtAddEditRecordDataNsNameServer").val(divData.attr("data-record-value"));
            $("#txtAddEditRecordDataNsGlue").val(divData.attr("data-record-glue").replace(/, /g, "\n"));

            if (disableEditRecordModalFields) {
                $("#txtAddEditRecordName").prop("disabled", true);
                $("#txtAddEditRecordTtl").prop("disabled", true);

                $("#txtAddEditRecordDataNsNameServer").prop("disabled", true);
            }
            break;

        case "SOA":
            $("#txtEditRecordDataSoaPrimaryNameServer").val(divData.attr("data-record-mname"));
            $("#txtEditRecordDataSoaResponsiblePerson").val(divData.attr("data-record-rperson"));
            $("#txtEditRecordDataSoaSerial").val(divData.attr("data-record-serial"));
            $("#txtEditRecordDataSoaRefresh").val(divData.attr("data-record-refresh"));
            $("#txtEditRecordDataSoaRetry").val(divData.attr("data-record-retry"));
            $("#txtEditRecordDataSoaExpire").val(divData.attr("data-record-expire"));
            $("#txtEditRecordDataSoaMinimum").val(divData.attr("data-record-minimum"));
            $("#txtEditRecordDataSoaGlue").val(divData.attr("data-record-glue").replace(/, /g, "\n"));

            $("#txtAddEditRecordName").prop("disabled", true);

            if (disableEditRecordModalFields) {
                $("#txtAddEditRecordTtl").prop("disabled", true);

                $("#txtEditRecordDataSoaPrimaryNameServer").prop("disabled", true);
                $("#txtEditRecordDataSoaResponsiblePerson").prop("disabled", true);
                $("#txtEditRecordDataSoaSerial").prop("disabled", true);
                $("#txtEditRecordDataSoaRefresh").prop("disabled", true);
                $("#txtEditRecordDataSoaRetry").prop("disabled", true);
                $("#txtEditRecordDataSoaExpire").prop("disabled", true);
                $("#txtEditRecordDataSoaMinimum").prop("disabled", true);
            }

            if (hideEditRecordGlueField) {
                $("#divEditRecordDataSoaGlue").hide();
            } else {
                $("#divEditRecordDataSoaGlue").show();
            }

            break;

        case "MX":
            $("#txtAddEditRecordDataMxPreference").val(divData.attr("data-record-preference"));
            $("#txtAddEditRecordDataMxExchange").val(divData.attr("data-record-value"));
            break;

        case "SRV":
            $("#txtAddEditRecordDataSrvPriority").val(divData.attr("data-record-priority"));
            $("#txtAddEditRecordDataSrvWeight").val(divData.attr("data-record-weight"));
            $("#txtAddEditRecordDataSrvPort").val(divData.attr("data-record-port"));
            $("#txtAddEditRecordDataSrvTarget").val(divData.attr("data-record-value"));
            break;

        case "CAA":
            $("#txtAddEditRecordDataCaaFlags").val(divData.attr("data-record-flags"));
            $("#txtAddEditRecordDataCaaTag").val(divData.attr("data-record-tag"));
            $("#txtAddEditRecordDataCaaValue").val(divData.attr("data-record-value"));
            break;

        case "FWD":
            $("input[name=rdAddEditRecordDataForwarderProtocol]:radio").attr('disabled', true);
            $("#rdAddEditRecordDataForwarderProtocol" + divData.attr("data-record-protocol")).prop("checked", true);
            $("#txtAddEditRecordDataForwarder").val(divData.attr("data-record-value"));
            updateAddEditFormForwarderPlaceholder();
            break;

        default:
            showAlert("warning", "Not Supported!", "Record type not supported for edit.");
            return;
    }

    $("#optAddEditRecordType").prop("disabled", true);

    $("#btnAddEditRecord").attr("data-id", id);
    $("#btnAddEditRecord").attr("onclick", "updateRecord(); return false;");

    $("#modalAddEditRecord").modal("show");
}

function updateRecord() {
    var btn = $("#btnAddEditRecord");
    var divAddEditRecordAlert = $("#divAddEditRecordAlert");

    var id = btn.attr("data-id");
    var divData = $("#data" + id);

    var zone = $("#titleEditZone").text();
    var type = divData.attr("data-record-type");
    var domain = divData.attr("data-record-name");

    if (domain === "")
        domain = ".";

    var newDomain;
    {
        var newSubDomain = $("#txtAddEditRecordName").val();
        if (newSubDomain === "")
            newSubDomain = "@";

        if (newSubDomain === "@")
            newDomain = zone;
        else if (zone === ".")
            newDomain = newSubDomain + ".";
        else
            newDomain = newSubDomain + "." + zone;
    }

    var ttl = $("#txtAddEditRecordTtl").val();
    if (ttl === "")
        ttl = 3600;

    var value = divData.attr("data-record-value");
    var disable = (divData.attr("data-record-disabled") === "true");

    var apiUrl = "/api/updateRecord?token=" + token + "&type=" + type + "&domain=" + encodeURIComponent(domain) + "&newDomain=" + encodeURIComponent(newDomain) + "&ttl=" + ttl + "&value=" + encodeURIComponent(value) + "&disable=" + disable;

    switch (type) {
        case "A":
        case "AAAA":
            var newValue = $("#txtAddEditRecordDataValue").val();
            if (newValue === "") {
                showAlert("warning", "Missing!", "Please enter an IP address to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").focus();
                return;
            }

            apiUrl += "&newValue=" + encodeURIComponent(newValue) + "&ptr=" + $("#chkAddEditRecordDataPtr").prop('checked');
            break;

        case "PTR":
        case "TXT":
        case "ANAME":
            var newValue = $("#txtAddEditRecordDataValue").val();
            if (newValue === "") {
                showAlert("warning", "Missing!", "Please enter a suitable value to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").focus();
                return;
            }

            apiUrl += "&newValue=" + encodeURIComponent(newValue);
            break;

        case "CNAME":
            var subDomainName = $("#txtAddEditRecordName").val();
            if ((subDomainName === "") || (subDomainName === "@")) {
                showAlert("warning", "Missing!", "Please enter a name for the CNAME record.", divAddEditRecordAlert);
                $("#txtAddEditRecordName").focus();
                return;
            }

            var newValue = $("#txtAddEditRecordDataValue").val();
            if (newValue === "") {
                showAlert("warning", "Missing!", "Please enter a domain name to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").focus();
                return;
            }

            apiUrl += "&newValue=" + encodeURIComponent(newValue);
            break;

        case "NS":
            var newValue = $("#txtAddEditRecordDataNsNameServer").val();
            if (newValue === "") {
                showAlert("warning", "Missing!", "Please enter a name server to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataNsNameServer").focus();
                return;
            }

            var glue = cleanTextList($("#txtAddEditRecordDataNsGlue").val());

            apiUrl += "&newValue=" + encodeURIComponent(newValue) + "&glue=" + encodeURIComponent(glue);
            break;

        case "SOA":
            var primaryNameServer = $("#txtEditRecordDataSoaPrimaryNameServer").val();
            if (primaryNameServer === "") {
                showAlert("warning", "Missing!", "Please enter a value for primary name server.", divAddEditRecordAlert);
                $("#txtEditRecordDataSoaPrimaryNameServer").focus();
                return;
            }

            var responsiblePerson = $("#txtEditRecordDataSoaResponsiblePerson").val();
            if (responsiblePerson === "") {
                showAlert("warning", "Missing!", "Please enter a value for responsible person.", divAddEditRecordAlert);
                $("#txtEditRecordDataSoaResponsiblePerson").focus();
                return;
            }

            var serial = $("#txtEditRecordDataSoaSerial").val();
            if (serial === "") {
                showAlert("warning", "Missing!", "Please enter a value for serial.", divAddEditRecordAlert);
                $("#txtEditRecordDataSoaSerial").focus();
                return;
            }

            var refresh = $("#txtEditRecordDataSoaRefresh").val();
            if (refresh === "") {
                showAlert("warning", "Missing!", "Please enter a value for refresh.", divAddEditRecordAlert);
                $("#txtEditRecordDataSoaRefresh").focus();
                return;
            }

            var retry = $("#txtEditRecordDataSoaRetry").val();
            if (retry === "") {
                showAlert("warning", "Missing!", "Please enter a value for retry.", divAddEditRecordAlert);
                $("#txtEditRecordDataSoaRetry").focus();
                return;
            }

            var expire = $("#txtEditRecordDataSoaExpire").val();
            if (expire === "") {
                showAlert("warning", "Missing!", "Please enter a value for expire.", divAddEditRecordAlert);
                $("#txtEditRecordDataSoaExpire").focus();
                return;
            }

            var minimum = $("#txtEditRecordDataSoaMinimum").val();
            if (minimum === "") {
                showAlert("warning", "Missing!", "Please enter a value for minimum.", divAddEditRecordAlert);
                $("#txtEditRecordDataSoaMinimum").focus();
                return;
            }

            var glue = cleanTextList($("#txtEditRecordDataSoaGlue").val());

            apiUrl += "&primaryNameServer=" + encodeURIComponent(primaryNameServer) +
                "&responsiblePerson=" + encodeURIComponent(responsiblePerson) +
                "&serial=" + encodeURIComponent(serial) +
                "&refresh=" + encodeURIComponent(refresh) +
                "&retry=" + encodeURIComponent(retry) +
                "&expire=" + encodeURIComponent(expire) +
                "&minimum=" + encodeURIComponent(minimum) +
                "&glue=" + encodeURIComponent(glue);
            break;

        case "MX":
            var preference = $("#txtAddEditRecordDataMxPreference").val();
            if (preference === "")
                preference = 1;

            var newValue = $("#txtAddEditRecordDataMxExchange").val();
            if (newValue === "") {
                showAlert("warning", "Missing!", "Please enter a mail exchange domain name to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataMxExchange").focus();
                return;
            }

            apiUrl += "&preference=" + preference + "&newValue=" + encodeURIComponent(newValue);
            break;

        case "SRV":
            if ($("#txtAddEditRecordName").val() === "") {
                showAlert("warning", "Missing!", "Please enter a name that includes service and protocol labels.", divAddEditRecordAlert);
                $("#txtAddEditRecordName").focus();
                return;
            }

            var port = divData.attr("data-record-port");

            var priority = $("#txtAddEditRecordDataSrvPriority").val();
            if (priority === "") {
                showAlert("warning", "Missing!", "Please enter a suitable priority.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvPriority").focus();
                return;
            }

            var weight = $("#txtAddEditRecordDataSrvWeight").val();
            if (weight === "") {
                showAlert("warning", "Missing!", "Please enter a suitable weight.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvWeight").focus();
                return;
            }

            var newPort = $("#txtAddEditRecordDataSrvPort").val();
            if (newPort === "") {
                showAlert("warning", "Missing!", "Please enter a suitable port number.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvPort").focus();
                return;
            }

            var newValue = $("#txtAddEditRecordDataSrvTarget").val();
            if (newValue === "") {
                showAlert("warning", "Missing!", "Please enter a suitable value into the target field.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvTarget").focus();
                return;
            }

            apiUrl += "&port=" + port + "&priority=" + priority + "&weight=" + weight + "&newPort=" + newPort + "&newValue=" + encodeURIComponent(newValue);
            break;

        case "CAA":
            var flags = divData.attr("data-record-flags");
            var tag = divData.attr("data-record-tag");

            var newFlags = $("#txtAddEditRecordDataCaaFlags").val();
            if (newFlags === "")
                newFlags = 0;

            var newTag = $("#txtAddEditRecordDataCaaTag").val();
            if (newTag === "")
                newTag = "issue";

            var newValue = $("#txtAddEditRecordDataCaaValue").val();
            if (newValue === "") {
                showAlert("warning", "Missing!", "Please enter a suitable value into the authority field.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataCaaValue").focus();
                return;
            }

            apiUrl += "&flags=" + flags + "&tag=" + encodeURIComponent(tag) + "&newFlags=" + newFlags + "&newTag=" + encodeURIComponent(newTag) + "&newValue=" + encodeURIComponent(newValue);
            break;

        case "FWD":
            var newValue = $("#txtAddEditRecordDataForwarder").val();
            if (newValue === "") {
                showAlert("warning", "Missing!", "Please enter a domain name or IP address or URL as a forwarder to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataForwarder").focus();
                return;
            }

            apiUrl += "&protocol=" + $('input[name=rdAddEditRecordDataForwarderProtocol]:checked').val() + "&newValue=" + newValue;
            break;
    }

    btn.button('loading');

    HTTPRequest({
        url: apiUrl,
        success: function (responseJSON) {
            $("#modalAddEditRecord").modal("hide");
            showEditZone(zone);
            showAlert("success", "Record Updated!", "Resource record was updated successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            showPageLogin();
        },
        objAlertPlaceholder: divAddEditRecordAlert
    });
}

function updateRecordState(objBtn, disable) {
    var btn = $(objBtn);
    var id = btn.attr("data-id");
    var divData = $("#data" + id);

    var type = divData.attr("data-record-type");
    var domain = divData.attr("data-record-name");
    var ttl = divData.attr("data-record-ttl");
    var value = divData.attr("data-record-value");

    if (domain === "")
        domain = ".";

    if (disable && !confirm("Are you sure to disable the " + type + " record '" + domain + "' with value '" + value + "'?"))
        return;

    var apiUrl = "/api/updateRecord?token=" + token + "&type=" + type + "&domain=" + encodeURIComponent(domain) + "&ttl=" + ttl + "&value=" + encodeURIComponent(value) + "&disable=" + disable;

    switch (type) {
        case "NS":
            apiUrl += "&glue=" + encodeURIComponent(divData.attr("data-record-glue"));
            break;

        case "MX":
            apiUrl += "&preference=" + divData.attr("data-record-preference");
            break;

        case "SRV":
            apiUrl += "&port=" + divData.attr("data-record-port") + "&priority=" + divData.attr("data-record-priority") + "&weight=" + divData.attr("data-record-weight");
            break;

        case "CAA":
            apiUrl += "&flags=" + divData.attr("data-record-flags") + "&tag=" + encodeURIComponent(divData.attr("data-record-tag"));
            break;

        case "FWD":
            apiUrl += "&protocol=" + divData.attr("data-record-protocol");
            break;
    }

    btn.button('loading');

    HTTPRequest({
        url: apiUrl,
        success: function (responseJSON) {
            btn.button('reset');

            if (disable) {
                $("#btnEnableRecord" + id).show();
                $("#btnDisableRecord" + id).hide();

                showAlert("success", "Record Disabled!", "Resource record was disabled successfully.");
            }
            else {
                $("#btnEnableRecord" + id).hide();
                $("#btnDisableRecord" + id).show();

                showAlert("success", "Record Enabled!", "Resource record was enabled successfully.");
            }
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function deleteRecord(objBtn) {
    var btn = $(objBtn);
    var id = btn.attr("data-id");
    var divData = $("#data" + id);

    var domain = divData.attr("data-record-name");
    var type = divData.attr("data-record-type");
    var value = divData.attr("data-record-value");

    if (domain === "")
        domain = ".";

    if (!confirm("Are you sure to permanently delete the " + type + " record '" + domain + "' with value '" + value + "'?"))
        return false;

    var apiUrl = "/api/deleteRecord?token=" + token + "&domain=" + domain + "&type=" + type + "&value=" + encodeURIComponent(value);

    switch (type) {
        case "SRV":
            apiUrl += "&port=" + divData.attr("data-record-port");
            break;

        case "CAA":
            apiUrl += "&flags=" + divData.attr("data-record-flags") + "&tag=" + encodeURIComponent(divData.attr("data-record-tag"));
            break;

        case "FWD":
            apiUrl += "&protocol=" + divData.attr("data-record-protocol");
            break;
    }

    btn.button('loading');

    HTTPRequest({
        url: apiUrl,
        success: function (responseJSON) {
            $("#tr" + id).remove();
            $("#tableEditZoneFooter").html("<tr><td colspan=\"5\"><b>Total Records: " + $('#tableEditZone >tbody >tr').length + "</b></td></tr>");

            showAlert("success", "Record Deleted!", "Resource record was deleted successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}
