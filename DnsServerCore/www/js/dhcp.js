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

function refreshDhcpTab() {

    if ($("#dhcpTabListLeases").hasClass("active"))
        refreshDhcpLeases();
    else if ($("#dhcpTabListScopes").hasClass("active"))
        refreshDhcpScopes(true);
    else
        refreshDhcpLeases();
}

function refreshDhcpLeases() {

    var divDhcpLeasesLoader = $("#divDhcpLeasesLoader");
    var divDhcpLeases = $("#divDhcpLeases");

    divDhcpLeases.hide();
    divDhcpLeasesLoader.show();

    HTTPRequest({
        url: "/api/listDhcpLeases?token=" + token,
        success: function (responseJSON) {
            var dhcpLeases = responseJSON.response.leases;
            var tableHtmlRows = "";

            for (var i = 0; i < dhcpLeases.length; i++) {
                tableHtmlRows += "<tr><td>" + htmlEncode(dhcpLeases[i].scope) + "</td><td>" +
                    dhcpLeases[i].hardwareAddress + "</td><td>" +
                    dhcpLeases[i].address + "</td><td><span id=\"spanDhcpLeaseType" + i + "\" class=\"label label-" +
                    (dhcpLeases[i].type === "Reserved" ? "default" : "primary") + "\">" + dhcpLeases[i].type + "</span></td><td>" +
                    htmlEncode(dhcpLeases[i].hostName) + "</td><td>" +
                    dhcpLeases[i].leaseObtained + "</td><td>" +
                    dhcpLeases[i].leaseExpires +
                    "</td><td><button id=\"btnDhcpLeaseReserve" + i + "\" type=\"button\" class=\"btn btn-default\" style=\"" + (dhcpLeases[i].type === "Dynamic" ? "" : "display: none;") + "font-size: 12px; padding: 2px 0px; width: 70px;\" data-loading-text=\"Working...\" onclick=\"convertToReservedLease(this, " + i + ", '" + dhcpLeases[i].scope + "', '" + dhcpLeases[i].hardwareAddress + "');\">Reserve</button>" +
                    "<button id=\"btnDhcpLeaseUnreserve" + i + "\" type=\"button\" class=\"btn btn-default\" style=\"" + (dhcpLeases[i].type === "Dynamic" ? "display: none;" : "") + "font-size: 12px; padding: 2px 0px; width: 70px;\" data-loading-text=\"Working...\" onclick=\"convertToDynamicLease(this, " + i + ", '" + dhcpLeases[i].scope + "', '" + dhcpLeases[i].hardwareAddress + "');\">Unreserve</button></td></tr>";
            }

            $("#tableDhcpLeasesBody").html(tableHtmlRows);

            if (dhcpLeases.length > 0)
                $("#tableDhcpLeasesFooter").html("<tr><td colspan=\"8\"><b>Total Leases: " + dhcpLeases.length + "</b></td></tr>");
            else
                $("#tableDhcpLeasesFooter").html("<tr><td colspan=\"8\" align=\"center\">No Lease Found</td></tr>");

            divDhcpLeasesLoader.hide();
            divDhcpLeases.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divDhcpLeasesLoader
    });
}

function convertToReservedLease(objBtn, index, scopeName, hardwareAddress) {

    if (!confirm("Are you sure you want to convert the dynamic lease to reserved lease?"))
        return false;

    var btn = $(objBtn);
    btn.button('loading');

    HTTPRequest({
        url: "/api/convertToReservedLease?token=" + token + "&name=" + encodeURIComponent(scopeName) + "&hardwareAddress=" + encodeURIComponent(hardwareAddress),
        success: function (responseJSON) {
            btn.button('reset');
            btn.hide();

            $("#btnDhcpLeaseUnreserve" + index).show();

            var spanDhcpLeaseType = $("#spanDhcpLeaseType" + index);
            spanDhcpLeaseType.html("Reserved");
            spanDhcpLeaseType.attr("class", "label label-default");

            showAlert("success", "Reserved!", "The dynamic lease was converted to reserved lease successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function convertToDynamicLease(objBtn, index, scopeName, hardwareAddress) {

    if (!confirm("Are you sure you want to convert the reserved lease to dynamic lease?"))
        return false;

    var btn = $(objBtn);
    btn.button('loading');

    HTTPRequest({
        url: "/api/convertToDynamicLease?token=" + token + "&name=" + encodeURIComponent(scopeName) + "&hardwareAddress=" + encodeURIComponent(hardwareAddress),
        success: function (responseJSON) {
            btn.button('reset');
            btn.hide();

            $("#btnDhcpLeaseReserve" + index).show();

            var spanDhcpLeaseType = $("#spanDhcpLeaseType" + index);
            spanDhcpLeaseType.html("Dynamic");
            spanDhcpLeaseType.attr("class", "label label-primary");

            showAlert("success", "Unreserved!", "The reserved lease was converted to dynamic lease successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function refreshDhcpScopes(checkDisplay) {

    if (checkDisplay == null)
        checkDisplay = false;

    var divDhcpViewScopes = $("#divDhcpViewScopes");

    if (checkDisplay && (divDhcpViewScopes.css('display') === "none"))
        return;

    var divDhcpViewScopesLoader = $("#divDhcpViewScopesLoader");
    var divDhcpEditScope = $("#divDhcpEditScope");

    divDhcpViewScopes.hide();
    divDhcpEditScope.hide();
    divDhcpViewScopesLoader.show();

    HTTPRequest({
        url: "/api/listDhcpScopes?token=" + token,
        success: function (responseJSON) {
            var dhcpScopes = responseJSON.response.scopes;
            var tableHtmlRows = "";

            for (var i = 0; i < dhcpScopes.length; i++) {
                tableHtmlRows += "<tr><td>" + htmlEncode(dhcpScopes[i].name) + "</td><td>" + dhcpScopes[i].startingAddress + " - " + dhcpScopes[i].endingAddress + "<br />" + dhcpScopes[i].subnetMask + "</td><td>" + dhcpScopes[i].networkAddress + "<br />" + dhcpScopes[i].broadcastAddress + "</td><td>" + (dhcpScopes[i].interfaceAddress == null ? "" : dhcpScopes[i].interfaceAddress) + "</td>";
                tableHtmlRows += "<td align=\"right\"><button type=\"button\" class=\"btn btn-primary\" style=\"font-size: 12px; padding: 2px 0px; width: 60px; margin: 0 6px 6px 0;\" onclick=\"showEditDhcpScope('" + dhcpScopes[i].name + "');\">Edit</button>";

                if (dhcpScopes[i].enabled)
                    tableHtmlRows += "<button type=\"button\" class=\"btn btn-warning\" style=\"font-size: 12px; padding: 2px 0px; width: 60px; margin: 0 6px 6px 0;\" onclick=\"disableDhcpScope('" + dhcpScopes[i].name + "');\">Disable</button>";
                else
                    tableHtmlRows += "<button type=\"button\" class=\"btn btn-default\" style=\"font-size: 12px; padding: 2px 0px; width: 60px; margin: 0 6px 6px 0;\" onclick=\"enableDhcpScope('" + dhcpScopes[i].name + "');\">Enable</button>";

                tableHtmlRows += "<button type=\"button\" class=\"btn btn-danger\" style=\"font-size: 12px; padding: 2px 0px; width: 60px; margin: 0 6px 6px 0;\" onclick=\"deleteDhcpScope('" + dhcpScopes[i].name + "');\">Delete</button></td></tr>";
            }

            $("#tableDhcpScopesBody").html(tableHtmlRows);

            if (dhcpScopes.length > 0)
                $("#tableDhcpScopesFooter").html("<tr><td colspan=\"5\"><b>Total Scopes: " + dhcpScopes.length + "</b></td></tr>");
            else
                $("#tableDhcpScopesFooter").html("<tr><td colspan=\"5\" align=\"center\">No Scope Found</td></tr>");

            divDhcpViewScopesLoader.hide();
            divDhcpViewScopes.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divDhcpViewScopesLoader
    });
}

function addDhcpScopeStaticRouteRow(destination, subnetMask, router) {

    var id = Math.floor(Math.random() * 10000);

    var tableHtmlRows = "<tr id=\"tableDhcpScopeStaticRoutesRow" + id + "\"><td><input type=\"text\" class=\"form-control\" value=\"" + htmlEncode(destination) + "\"></td>";
    tableHtmlRows += "<td><input type=\"text\" class=\"form-control\" value=\"" + htmlEncode(subnetMask) + "\"></td>";
    tableHtmlRows += "<td><input type=\"text\" class=\"form-control\" value=\"" + htmlEncode(router) + "\"></td>";
    tableHtmlRows += "<td><button type=\"button\" class=\"btn btn-danger\" onclick=\"$('#tableDhcpScopeStaticRoutesRow" + id + "').remove();\">Delete</button></td></tr>";

    $("#tableDhcpScopeStaticRoutes").append(tableHtmlRows);
}

function addDhcpScopeVendorInfoRow(identifier, information) {

    var id = Math.floor(Math.random() * 10000);

    var tableHtmlRows = "<tr id=\"tableDhcpScopeVendorInfoRow" + id + "\"><td><input type=\"text\" class=\"form-control\" value='" + htmlEncode(identifier) + "' data-optional=\"true\"></td>";
    tableHtmlRows += "<td><input type=\"text\" class=\"form-control\" value='" + htmlEncode(information) + "'></td>";
    tableHtmlRows += "<td><button type=\"button\" class=\"btn btn-danger\" onclick=\"$('#tableDhcpScopeVendorInfoRow" + id + "').remove();\">Delete</button></td></tr>";

    $("#tableDhcpScopeVendorInfo").append(tableHtmlRows);
}

function addDhcpScopeExclusionRow(startingAddress, endingAddress) {

    var id = Math.floor(Math.random() * 10000);

    var tableHtmlRows = "<tr id=\"tableDhcpScopeExclusionRow" + id + "\"><td><input type=\"text\" class=\"form-control\" value=\"" + htmlEncode(startingAddress) + "\"></td>";
    tableHtmlRows += "<td><input type=\"text\" class=\"form-control\" value=\"" + htmlEncode(endingAddress) + "\"></td>";
    tableHtmlRows += "<td><button type=\"button\" class=\"btn btn-danger\" onclick=\"$('#tableDhcpScopeExclusionRow" + id + "').remove();\">Delete</button></td></tr>";

    $("#tableDhcpScopeExclusions").append(tableHtmlRows);
}

function addDhcpScopeReservedLeaseRow(hostName, hardwareAddress, address, comments) {

    var id = Math.floor(Math.random() * 10000);

    var tableHtmlRows = "<tr id=\"tableDhcpScopeReservedLeaseRow" + id + "\">";
    tableHtmlRows += "<td><input type=\"text\" class=\"form-control\" value=\"" + (hostName == null ? "" : htmlEncode(hostName)) + "\" data-optional=\"true\"></td>";
    tableHtmlRows += "<td><input type=\"text\" class=\"form-control\" value=\"" + htmlEncode(hardwareAddress) + "\"></td>";
    tableHtmlRows += "<td><input type=\"text\" class=\"form-control\" value=\"" + htmlEncode(address) + "\"></td>";
    tableHtmlRows += "<td><input type=\"text\" class=\"form-control\" value=\"" + (comments == null ? "" : htmlEncode(comments)) + "\" data-optional=\"true\"></td>";
    tableHtmlRows += "<td><button type=\"button\" class=\"btn btn-danger\" onclick=\"$('#tableDhcpScopeReservedLeaseRow" + id + "').remove();\">Delete</button></td></tr>";

    $("#tableDhcpScopeReservedLeases").append(tableHtmlRows);
}

function serializeTableData(table, columns) {

    var data = table.find('input:text');
    var output = "";

    for (var i = 0; i < data.length; i += columns) {
        if (i > 0)
            output += "|";

        for (var j = 0; j < columns; j++) {
            if (j > 0)
                output += "|";

            var cell = $(data[i + j]);
            var cellValue = cell.val();
            var optional = (cell.attr("data-optional") === "true");

            if ((cellValue === "") && !optional) {
                showAlert("warning", "Missing!", "Please enter a valid value in the text field in focus.");
                cell.focus();
                return false;
            }

            output += htmlDecode(cellValue);
        }
    }

    return output;
}

function clearDhcpScopeForm() {
    $("#txtDhcpScopeName").attr("data-name", "");
    $("#txtDhcpScopeName").val("");
    $("#txtDhcpScopeStartingAddress").val("");
    $("#txtDhcpScopeEndingAddress").val("");
    $("#txtDhcpScopeSubnetMask").val("");
    $("#txtDhcpScopeLeaseTimeDays").val("1");
    $("#txtDhcpScopeLeaseTimeHours").val("0");
    $("#txtDhcpScopeLeaseTimeMinutes").val("0");
    $("#txtDhcpScopeOfferDelayTime").val("0");
    $("#txtDhcpScopeDomainName").val("");
    $("#txtDhcpScopeDnsTtl").val("900");
    $("#txtDhcpScopeServerAddress").val("");
    $("#txtDhcpScopeServerHostName").val("");
    $("#txtDhcpScopeBootFileName").val("");
    $("#txtDhcpScopeRouterAddress").val("");
    $("#chkUseThisDnsServer").prop("checked", false);
    $('#txtDhcpScopeDnsServers').prop('disabled', false);
    $("#txtDhcpScopeDnsServers").val("");
    $("#txtDhcpScopeWinsServers").val("");
    $("#txtDhcpScopeNtpServers").val("");
    $("#tableDhcpScopeStaticRoutes").html("");
    $("#tableDhcpScopeVendorInfo").html("");
    $("#tableDhcpScopeExclusions").html("");
    $("#tableDhcpScopeReservedLeases").html("");
    $("#chkAllowOnlyReservedLeases").prop("checked", false);
    $("#btnSaveDhcpScope").button('reset');
}

function showAddDhcpScope() {

    clearDhcpScopeForm();

    $("#titleDhcpEditScope").html("Add Scope");
    $("#chkUseThisDnsServer").prop("checked", true);
    $('#txtDhcpScopeDnsServers').prop('disabled', true);
    $("#divDhcpViewScopes").hide();
    $("#divDhcpViewScopesLoader").hide();
    $("#divDhcpEditScope").show();
}

function showEditDhcpScope(scopeName) {

    clearDhcpScopeForm();

    $("#titleDhcpEditScope").html("Edit Scope");
    var divDhcpViewScopesLoader = $("#divDhcpViewScopesLoader");
    var divDhcpViewScopes = $("#divDhcpViewScopes");
    var divDhcpEditScope = $("#divDhcpEditScope");

    divDhcpViewScopes.hide();
    divDhcpEditScope.hide();
    divDhcpViewScopesLoader.show();

    HTTPRequest({
        url: "/api/getDhcpScope?token=" + token + "&name=" + scopeName,
        success: function (responseJSON) {
            $("#txtDhcpScopeName").attr("data-name", responseJSON.response.name);
            $("#txtDhcpScopeName").val(responseJSON.response.name);
            $("#txtDhcpScopeStartingAddress").val(responseJSON.response.startingAddress);
            $("#txtDhcpScopeEndingAddress").val(responseJSON.response.endingAddress);
            $("#txtDhcpScopeSubnetMask").val(responseJSON.response.subnetMask);
            $("#txtDhcpScopeLeaseTimeDays").val(responseJSON.response.leaseTimeDays);
            $("#txtDhcpScopeLeaseTimeHours").val(responseJSON.response.leaseTimeHours);
            $("#txtDhcpScopeLeaseTimeMinutes").val(responseJSON.response.leaseTimeMinutes);
            $("#txtDhcpScopeOfferDelayTime").val(responseJSON.response.offerDelayTime);

            if (responseJSON.response.domainName != null)
                $("#txtDhcpScopeDomainName").val(responseJSON.response.domainName);

            $("#txtDhcpScopeDnsTtl").val(responseJSON.response.dnsTtl);

            if (responseJSON.response.serverAddress != null)
                $("#txtDhcpScopeServerAddress").val(responseJSON.response.serverAddress);

            if (responseJSON.response.serverHostName != null)
                $("#txtDhcpScopeServerHostName").val(responseJSON.response.serverHostName);

            if (responseJSON.response.bootFileName != null)
                $("#txtDhcpScopeBootFileName").val(responseJSON.response.bootFileName);

            if (responseJSON.response.routerAddress != null)
                $("#txtDhcpScopeRouterAddress").val(responseJSON.response.routerAddress);

            $("#chkUseThisDnsServer").prop("checked", responseJSON.response.useThisDnsServer);
            $('#txtDhcpScopeDnsServers').prop('disabled', responseJSON.response.useThisDnsServer);

            if (responseJSON.response.dnsServers != null)
                $("#txtDhcpScopeDnsServers").val(responseJSON.response.dnsServers.join("\n"));

            if (responseJSON.response.winsServers != null)
                $("#txtDhcpScopeWinsServers").val(responseJSON.response.winsServers.join("\n"));

            if (responseJSON.response.ntpServers != null)
                $("#txtDhcpScopeNtpServers").val(responseJSON.response.ntpServers.join("\n"));

            if (responseJSON.response.staticRoutes != null) {
                for (var i = 0; i < responseJSON.response.staticRoutes.length; i++) {
                    addDhcpScopeStaticRouteRow(responseJSON.response.staticRoutes[i].destination, responseJSON.response.staticRoutes[i].subnetMask, responseJSON.response.staticRoutes[i].router);
                }
            }

            if (responseJSON.response.vendorInfo != null) {
                for (var i = 0; i < responseJSON.response.vendorInfo.length; i++) {
                    addDhcpScopeVendorInfoRow(responseJSON.response.vendorInfo[i].identifier, responseJSON.response.vendorInfo[i].information)
                }
            }

            if (responseJSON.response.exclusions != null) {
                for (var i = 0; i < responseJSON.response.exclusions.length; i++) {
                    addDhcpScopeExclusionRow(responseJSON.response.exclusions[i].startingAddress, responseJSON.response.exclusions[i].endingAddress);
                }
            }

            if (responseJSON.response.reservedLeases != null) {
                for (var i = 0; i < responseJSON.response.reservedLeases.length; i++) {
                    addDhcpScopeReservedLeaseRow(responseJSON.response.reservedLeases[i].hostName, responseJSON.response.reservedLeases[i].hardwareAddress, responseJSON.response.reservedLeases[i].address, responseJSON.response.reservedLeases[i].comments);
                }
            }

            $("#chkAllowOnlyReservedLeases").prop("checked", responseJSON.response.allowOnlyReservedLeases);

            divDhcpViewScopesLoader.hide();
            divDhcpEditScope.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divDhcpViewScopesLoader
    });
}

function saveDhcpScope() {

    var oldName = $("#txtDhcpScopeName").attr("data-name");
    var name = $("#txtDhcpScopeName").val();
    var newName = null;

    if ((oldName !== "") && (oldName != name)) {
        newName = name;
        name = oldName;
    }

    var startingAddress = $("#txtDhcpScopeStartingAddress").val();
    var endingAddress = $("#txtDhcpScopeEndingAddress").val();
    var subnetMask = $("#txtDhcpScopeSubnetMask").val();

    var leaseTimeDays = $("#txtDhcpScopeLeaseTimeDays").val();
    var leaseTimeHours = $("#txtDhcpScopeLeaseTimeHours").val();
    var leaseTimeMinutes = $("#txtDhcpScopeLeaseTimeMinutes").val();
    var offerDelayTime = $("#txtDhcpScopeOfferDelayTime").val();

    var domainName = $("#txtDhcpScopeDomainName").val();
    var dnsTtl = $("#txtDhcpScopeDnsTtl").val();

    var serverAddress = $("#txtDhcpScopeServerAddress").val();
    var serverHostName = $("#txtDhcpScopeServerHostName").val();
    var bootFileName = $("#txtDhcpScopeBootFileName").val();
    var routerAddress = $("#txtDhcpScopeRouterAddress").val();

    var useThisDnsServer = $("#chkUseThisDnsServer").prop('checked');
    var dnsServers = cleanTextList($("#txtDhcpScopeDnsServers").val());
    var winsServers = cleanTextList($("#txtDhcpScopeWinsServers").val());
    var ntpServers = cleanTextList($("#txtDhcpScopeNtpServers").val());

    var staticRoutes = serializeTableData($("#tableDhcpScopeStaticRoutes"), 3);
    if (staticRoutes === false)
        return;

    var vendorInfo = serializeTableData($("#tableDhcpScopeVendorInfo"), 2);
    if (vendorInfo === false)
        return;

    var exclusions = serializeTableData($("#tableDhcpScopeExclusions"), 2);
    if (exclusions === false)
        return;

    var reservedLeases = serializeTableData($("#tableDhcpScopeReservedLeases"), 4);
    if (reservedLeases === false)
        return;

    var allowOnlyReservedLeases = $("#chkAllowOnlyReservedLeases").prop('checked');

    var btn = $("#btnSaveDhcpScope").button('loading');

    HTTPRequest({
        url: "/api/setDhcpScope?token=" + token + "&name=" + encodeURIComponent(name) + (newName == null ? "" : "&newName=" + encodeURIComponent(newName)) + "&startingAddress=" + encodeURIComponent(startingAddress) + "&endingAddress=" + encodeURIComponent(endingAddress) + "&subnetMask=" + encodeURIComponent(subnetMask) +
            "&leaseTimeDays=" + leaseTimeDays + "&leaseTimeHours=" + leaseTimeHours + "&leaseTimeMinutes=" + leaseTimeMinutes + "&offerDelayTime=" + offerDelayTime + "&domainName=" + encodeURIComponent(domainName) + "&dnsTtl=" + dnsTtl + "&serverAddress=" + encodeURIComponent(serverAddress) + "&serverHostName=" + encodeURIComponent(serverHostName) + "&bootFileName=" + encodeURIComponent(bootFileName) +
            "&routerAddress=" + encodeURIComponent(routerAddress) + "&useThisDnsServer=" + useThisDnsServer + (useThisDnsServer ? "" : "&dnsServers=" + encodeURIComponent(dnsServers)) + "&winsServers=" + encodeURIComponent(winsServers) + "&ntpServers=" + encodeURIComponent(ntpServers) +
            "&staticRoutes=" + encodeURIComponent(staticRoutes) + "&vendorInfo=" + encodeURIComponent(vendorInfo) + "&exclusions=" + encodeURIComponent(exclusions) + "&reservedLeases=" + encodeURIComponent(reservedLeases) + "&allowOnlyReservedLeases=" + allowOnlyReservedLeases,
        success: function (responseJSON) {
            refreshDhcpScopes();
            btn.button('reset');
            showAlert("success", "Scope Saved!", "DHCP Scope was saved successfully.");
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

function disableDhcpScope(scopeName) {

    if (!confirm("Are you sure you want to disable the DHCP scope '" + scopeName + "'?"))
        return false;

    var divDhcpViewScopesLoader = $("#divDhcpViewScopesLoader");
    var divDhcpViewScopes = $("#divDhcpViewScopes");
    var divDhcpEditScope = $("#divDhcpEditScope");

    divDhcpViewScopes.hide();
    divDhcpEditScope.hide();
    divDhcpViewScopesLoader.show();

    HTTPRequest({
        url: "/api/disableDhcpScope?token=" + token + "&name=" + scopeName,
        success: function (responseJSON) {
            refreshDhcpScopes();
            showAlert("success", "Scope Disabled!", "DHCP Scope was disabled successfully.");
        },
        error: function () {
            divDhcpViewScopesLoader.hide();
            divDhcpViewScopes.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divDhcpViewScopesLoader
    });
}

function enableDhcpScope(scopeName) {

    var divDhcpViewScopesLoader = $("#divDhcpViewScopesLoader");
    var divDhcpViewScopes = $("#divDhcpViewScopes");
    var divDhcpEditScope = $("#divDhcpEditScope");

    divDhcpViewScopes.hide();
    divDhcpEditScope.hide();
    divDhcpViewScopesLoader.show();

    HTTPRequest({
        url: "/api/enableDhcpScope?token=" + token + "&name=" + scopeName,
        success: function (responseJSON) {
            refreshDhcpScopes();
            showAlert("success", "Scope Enabled!", "DHCP Scope was enabled successfully.");
        },
        error: function () {
            divDhcpViewScopesLoader.hide();
            divDhcpViewScopes.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divDhcpViewScopesLoader
    });
}

function deleteDhcpScope(scopeName) {

    if (!confirm("Are you sure you want to delete the DHCP scope '" + scopeName + "'?"))
        return false;

    var divDhcpViewScopesLoader = $("#divDhcpViewScopesLoader");
    var divDhcpViewScopes = $("#divDhcpViewScopes");
    var divDhcpEditScope = $("#divDhcpEditScope");

    divDhcpViewScopes.hide();
    divDhcpEditScope.hide();
    divDhcpViewScopesLoader.show();

    HTTPRequest({
        url: "/api/deleteDhcpScope?token=" + token + "&name=" + scopeName,
        success: function (responseJSON) {
            refreshDhcpScopes();
            showAlert("success", "Scope Deleted!", "DHCP Scope was deleted successfully.");
        },
        error: function () {
            divDhcpViewScopesLoader.hide();
            divDhcpViewScopes.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divDhcpViewScopesLoader
    });
}
