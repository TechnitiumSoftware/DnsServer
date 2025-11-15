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
    $("#optInitializeNewClusterQuickIpAddresses").on("change", function () {
        var selectedIpAddress = $("#optInitializeNewClusterQuickIpAddresses").val();
        switch (selectedIpAddress) {
            case "blank":
                break;

            default:
                var existingList = $("#txtInitializeNewClusterPrimaryNodeIpAddresses").val();

                if (existingList.indexOf(selectedIpAddress) < 0) {
                    existingList += selectedIpAddress + "\n";
                    $("#txtInitializeNewClusterPrimaryNodeIpAddresses").val(existingList);
                }

                break;
        }
    });

    $("#optInitializeJoinClusterQuickIpAddresses").on("change", function () {
        var selectedIpAddress = $("#optInitializeJoinClusterQuickIpAddresses").val();
        switch (selectedIpAddress) {
            case "blank":
                break;

            default:
                var existingList = $("#txtInitializeJoinClusterSecondaryNodeIpAddresses").val();

                if (existingList.indexOf(selectedIpAddress) < 0) {
                    existingList += selectedIpAddress + "\n";
                    $("#txtInitializeJoinClusterSecondaryNodeIpAddresses").val(existingList);
                }

                break;
        }
    });

    $("#optEditClusterNodeQuickSelfIpAddresses").on("change", function () {
        var selectedIpAddress = $("#optEditClusterNodeQuickSelfIpAddresses").val();
        switch (selectedIpAddress) {
            case "blank":
                break;

            default:
                var existingList = $("#txtEditClusterNodeSelfNodeIpAddresses").val();

                if (existingList.indexOf(selectedIpAddress) < 0) {
                    existingList += selectedIpAddress + "\n";
                    $("#txtEditClusterNodeSelfNodeIpAddresses").val(existingList);
                }

                break;
        }
    });
});

function refreshAdminCluster() {
    var divAdminClusterLoader = $("#divAdminClusterLoader");
    var divAdminClusterView = $("#divAdminClusterView");

    var node = $("#optAdminClusterNode").val();

    divAdminClusterLoader.show();
    divAdminClusterView.hide();

    HTTPRequest({
        url: "api/admin/cluster/state?token=" + sessionData.token + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            reloadAdminClusterView(responseJSON);

            divAdminClusterLoader.hide();
            divAdminClusterView.show();
        },
        error: function () {
            divAdminClusterLoader.hide();
            divAdminClusterView.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divAdminClusterLoader
    });
}

function updateAdminClusterDataAndGui(responseJSON) {
    sessionData.info.dnsServerDomain = responseJSON.response.dnsServerDomain;
    sessionData.info.clusterDomain = responseJSON.response.clusterDomain;

    document.title = responseJSON.response.dnsServerDomain + " - " + "Technitium DNS Server v" + responseJSON.response.version;
    $("#lblAboutVersion").text(responseJSON.response.version);
    $("#lblDnsServerDomain").text(" - " + responseJSON.response.dnsServerDomain);
}

function reloadAdminClusterView(responseJSON) {
    sessionData.info.clusterInitialized = responseJSON.response.clusterInitialized;
    sessionData.info.clusterNodes = responseJSON.response.clusterNodes;
    updateAllClusterNodeDropDowns();

    if (responseJSON.response.clusterInitialized) {
        var selfNodeType;

        for (var i = 0; i < responseJSON.response.clusterNodes.length; i++) {
            if (responseJSON.response.clusterNodes[i].state == "Self") {
                selfNodeType = responseJSON.response.clusterNodes[i].type;
                break;
            }
        }

        var tableHtmlRows = "";

        for (var i = 0; i < responseJSON.response.clusterNodes.length; i++) {
            var ipAddresses = "";
            var ipAddressesCsv = "";

            for (var j = 0; j < responseJSON.response.clusterNodes[i].ipAddresses.length; j++) {
                ipAddresses += htmlEncode(responseJSON.response.clusterNodes[i].ipAddresses[j]) + "</br>";

                if (ipAddressesCsv.length == 0)
                    ipAddressesCsv = responseJSON.response.clusterNodes[i].ipAddresses[j];
                else
                    ipAddressesCsv += "," + responseJSON.response.clusterNodes[i].ipAddresses[j];
            }

            var nodeType;

            switch (responseJSON.response.clusterNodes[i].type) {
                case "Primary":
                    nodeType = "<span class=\"label label-primary\">Primary</span>";
                    break;

                case "Secondary":
                    nodeType = "<span class=\"label label-primary\">Secondary</span>";
                    break;

                default:
                    nodeType = "<span class=\"label label-warning\">Unknown</span>";
                    break;
            }

            var clusterNodestate;

            switch (responseJSON.response.clusterNodes[i].state) {
                case "Self":
                    clusterNodestate = "<span class=\"label label-default\">Self</span>";
                    break;

                case "Connected":
                    clusterNodestate = "<span class=\"label label-success\">Connected</span>";
                    break;

                case "Unreachable":
                    clusterNodestate = "<span class=\"label label-warning\">Unreachable</span>";
                    break;

                default:
                    clusterNodestate = "<span class=\"label label-warning\">Unknown</span>";
                    break;
            }

            var upSince = "";

            if (responseJSON.response.clusterNodes[i].upSince != null)
                upSince = moment(responseJSON.response.clusterNodes[i].upSince).local().format("YYYY-MM-DD HH:mm") + "<br /><span style=\"font-size: 12px\">(" + moment(responseJSON.response.clusterNodes[i].upSince).fromNow() + ")</span>";

            var lastSeen = "";
            var lastSynced = "";

            switch (responseJSON.response.clusterNodes[i].state) {
                case "Self":
                    if (responseJSON.response.clusterNodes[i].type == "Secondary") {
                        if (responseJSON.response.clusterNodes[i].configLastSynced != null)
                            lastSynced = moment(responseJSON.response.clusterNodes[i].configLastSynced).local().format("YYYY-MM-DD HH:mm") + "<br /><span style=\"font-size: 12px\">(" + moment(responseJSON.response.clusterNodes[i].configLastSynced).fromNow() + ")</span>";
                    }
                    break;

                default:
                    if (responseJSON.response.clusterNodes[i].lastSeen != null)
                        lastSeen = moment(responseJSON.response.clusterNodes[i].lastSeen).local().format("YYYY-MM-DD HH:mm") + "<br /><span style=\"font-size: 12px\">(" + moment(responseJSON.response.clusterNodes[i].lastSeen).fromNow() + ")</span>";

                    break;
            }

            tableHtmlRows += "<tr id=\"trAdminClusterNode" + i + "\"><td>" + htmlEncode(responseJSON.response.clusterNodes[i].name) + "</td><td>" +
                ipAddresses + "</td><td>" +
                htmlEncode(responseJSON.response.clusterNodes[i].url) + "</td><td>" +
                nodeType + "</td><td>" +
                clusterNodestate + "</td><td>" +
                upSince + "</td><td>" +
                lastSeen + "</td><td>" +
                lastSynced;

            tableHtmlRows += "</td>";

            tableHtmlRows += "<td align=\"right\">";

            switch (selfNodeType) {
                case "Primary":
                    tableHtmlRows += "<div class=\"dropdown\"><a href=\"#\" id=\"btnAdminClusterNodeRowOption" + i + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";

                    if (responseJSON.response.clusterNodes[i].state == "Self")
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" data-node-name=\"" + htmlEncode(responseJSON.response.clusterNodes[i].name) + "\" data-node-ip=\"" + ipAddressesCsv + "\" onclick=\"showEditSelfClusterNodeModal(this); return false;\">Edit Node</a></li>";

                    if (responseJSON.response.clusterNodes[i].type == "Secondary")
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" data-node-id=\"" + htmlEncode(responseJSON.response.clusterNodes[i].id) + "\" data-node-name=\"" + htmlEncode(responseJSON.response.clusterNodes[i].name) + "\" onclick=\"showRemoveSecondaryClusterNodeModal(this); return false;\">Remove Node</a></li>";

                    tableHtmlRows += "</ul></div>";
                    break;

                case "Secondary":
                    if (responseJSON.response.clusterNodes[i].state == "Self") {
                        tableHtmlRows += "<div class=\"dropdown\"><a href=\"#\" id=\"btnAdminClusterNodeRowOption" + i + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";

                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" data-node-name=\"" + htmlEncode(responseJSON.response.clusterNodes[i].name) + "\" data-node-ip=\"" + ipAddressesCsv + "\" onclick=\"showEditSelfClusterNodeModal(this); return false;\">Edit Node</a></li>";
                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" data-node-name=\"" + htmlEncode(responseJSON.response.clusterNodes[i].name) + "\" onclick=\"showPromoteToPrimaryClusterNodeModal(this); return false;\">Promote To Primary</a></li>";

                        tableHtmlRows += "</ul></div>";
                    }
                    else if (responseJSON.response.clusterNodes[i].type == "Primary") {
                        tableHtmlRows += "<div class=\"dropdown\"><a href=\"#\" id=\"btnAdminClusterNodeRowOption" + i + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";

                        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" data-node-name=\"" + htmlEncode(responseJSON.response.clusterNodes[i].name) + "\" data-node-url=\"" + htmlEncode(responseJSON.response.clusterNodes[i].url) + "\" data-node-ip=\"" + ipAddressesCsv + "\" onclick=\"showEditPrimaryClusterNodeModal(this); return false;\">Edit Node</a></li>";

                        tableHtmlRows += "</ul></div>";
                    }

                    break;
            }

            tableHtmlRows += "</td>";

            tableHtmlRows += "</tr>";
        }

        $("#divAdminClusterInitialize").hide();

        switch (selfNodeType) {
            case "Primary":
                $("#btnClusterResync").hide();
                $("#btnClusterOptions").show();
                $("#btnClusterLeave").hide();
                $("#btnClusterDelete").show();
                break;

            default:
                $("#btnClusterResync").show();
                $("#btnClusterOptions").show();
                $("#btnClusterLeave").show();
                $("#btnClusterDelete").hide();
                break;
        }

        $("#tbodyAdminCluster").html(tableHtmlRows);
        $("#tfootAdminCluster").html("Total Nodes: " + responseJSON.response.clusterNodes.length);
    }
    else {
        $("#divAdminClusterInitialize").show();
        $("#btnClusterResync").hide();
        $("#btnClusterOptions").hide();
        $("#btnClusterLeave").hide();
        $("#btnClusterDelete").hide();

        $("#tbodyAdminCluster").html("<tr><td colspan=\"9\" align=\"center\">Cluster Not Initialized</td></tr>");
        $("#tfootAdminCluster").html("");
    }
}

function showEditSelfClusterNodeModal(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var nodeName = mnuItem.attr("data-node-name");
    var nodeIp = mnuItem.attr("data-node-ip");

    var divEditClusterNodeAlert = $("#divEditClusterNodeAlert");
    var divEditClusterNodeLoader = $("#divEditClusterNodeLoader");
    var divEditClusterNodeView = $("#divEditClusterNodeView");

    var node = $("#optAdminClusterNode").val();

    $("#lblEditClusterNodeName").text(nodeName);

    $("#txtEditClusterNodeSelfNodeIpAddresses").val(nodeIp.replace(/,/g, "\n") + "\n");

    $("#divEditClusterNodeSelfNode").show();
    $("#divEditClusterNodePrimaryNode").hide();

    $("#btnEditClusterNodeSave").attr("onclick", "updateSelfClusterNode(this); return false;");

    divEditClusterNodeLoader.show();
    divEditClusterNodeView.hide();

    $("#modalEditClusterNode").modal("show");

    HTTPRequest({
        url: "api/admin/cluster/state?token=" + sessionData.token + "&includeServerIpAddresses=true" + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            var optionsHtml = "<option></option>";

            for (var i = 0; i < responseJSON.response.serverIpAddresses.length; i++)
                optionsHtml += "<option>" + responseJSON.response.serverIpAddresses[i] + "</option>";

            $("#optEditClusterNodeQuickSelfIpAddresses").html(optionsHtml);

            divEditClusterNodeLoader.hide();
            divEditClusterNodeView.show();

            setTimeout(function () {
                $("#optEditClusterNodeSelfNodeIpAddress").trigger("focus");
            }, 1000);
        },
        error: function () {
            divEditClusterNodeLoader.hide();
        },
        invalidToken: function () {
            $("#modalEditClusterNode").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divEditClusterNodeAlert,
        objLoaderPlaceholder: divEditClusterNodeLoader
    });
}

function updateSelfClusterNode(objBtn) {
    var divEditClusterNodeAlert = $("#divEditClusterNodeAlert");

    var ipAddresses = cleanTextList($("#txtEditClusterNodeSelfNodeIpAddresses").val());
    if ((ipAddresses.length === 0) || (ipAddresses === ",")) {
        showAlert("warning", "Missing!", "Please enter a node IP address.", divEditClusterNodeAlert);
        $("#txtEditClusterNodeSelfNodeIpAddresses").trigger("focus");
        return;
    }

    var node = $("#optAdminClusterNode").val();

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/admin/cluster/updateIpAddress?token=" + sessionData.token + "&ipAddresses=" + encodeURIComponent(ipAddresses) + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            btn.button("reset");
            $("#modalEditClusterNode").modal("hide");

            reloadAdminClusterView(responseJSON);

            showAlert("success", "Node Updated!", "Cluster node was updated successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalEditClusterNode").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divEditClusterNodeAlert
    });
}

function showEditPrimaryClusterNodeModal(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var nodeName = mnuItem.attr("data-node-name");
    var nodeUrl = mnuItem.attr("data-node-url");
    var nodeIp = mnuItem.attr("data-node-ip");

    $("#lblEditClusterNodeName").text(nodeName);
    $("#divEditClusterNodeSelfNode").hide();
    $("#txtEditClusterNodePrimaryNodeUrl").val(nodeUrl);
    $("#txtEditClusterNodePrimaryNodeIpAddresses").val(nodeIp.replace(/,/g, "\n") + "\n");
    $("#divEditClusterNodePrimaryNode").show();
    $("#btnEditClusterNodeSave").attr("onclick", "updatePrimaryClusterNode(this); return false;");

    hideAlert($("#divEditClusterNodeAlert"));

    $("#divEditClusterNodeLoader").hide();
    $("#divEditClusterNodeView").show();

    $("#modalEditClusterNode").modal("show");

    setTimeout(function () {
        $("#txtEditClusterNodePrimaryNodeUrl").trigger("focus");
    }, 1000);
}

function updatePrimaryClusterNode(objBtn) {
    var divEditClusterNodeAlert = $("#divEditClusterNodeAlert");

    var primaryNodeUrl = $("#txtEditClusterNodePrimaryNodeUrl").val();
    if (primaryNodeUrl === "") {
        showAlert("warning", "Missing!", "Please enter the Primary node URL.", divEditClusterNodeAlert);
        $("#txtEditClusterNodePrimaryNodeUrl").trigger("focus");
        return;
    }

    var primaryNodeIpAddresses = cleanTextList($("#txtEditClusterNodePrimaryNodeIpAddresses").val());
    if (primaryNodeIpAddresses === ",")
        primaryNodeIpAddresses = "";

    var node = $("#optAdminClusterNode").val();

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/admin/cluster/secondary/updatePrimary?token=" + sessionData.token + "&primaryNodeUrl=" + encodeURIComponent(primaryNodeUrl) + "&primaryNodeIpAddresses=" + encodeURIComponent(primaryNodeIpAddresses) + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            btn.button("reset");
            $("#modalEditClusterNode").modal("hide");

            reloadAdminClusterView(responseJSON);

            showAlert("success", "Node Updated!", "Cluster node was updated successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalEditClusterNode").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divEditClusterNodeAlert
    });
}

function showRemoveSecondaryClusterNodeModal(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var secondaryNodeId = mnuItem.attr("data-node-id");
    var nodeName = mnuItem.attr("data-node-name");

    hideAlert($("#divRemoveClusterNodeAlert"));
    $("#lblRemoveClusterNodeName").text(nodeName);
    $("#chkRemoveClusterNodeForceRemove").prop("checked", false);
    $("#btnRemoveClusterNode").attr("data-node-id", secondaryNodeId);

    $("#modalRemoveClusterNode").modal("show");
}

function removeSecondaryClusterNode(objBtn) {
    var divRemoveClusterNodeAlert = $("#divRemoveClusterNodeAlert");
    var btn = $(objBtn);

    var secondaryNodeId = btn.attr("data-node-id");
    var forceRemove = $("#chkRemoveClusterNodeForceRemove").prop("checked");

    var apiUrl;

    if (forceRemove)
        apiUrl = "api/admin/cluster/primary/deleteSecondary";
    else
        apiUrl = "api/admin/cluster/primary/removeSecondary";

    var node = $("#optAdminClusterNode").val();

    btn.button("loading");

    HTTPRequest({
        url: apiUrl + "?token=" + sessionData.token + "&secondaryNodeId=" + secondaryNodeId + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            btn.button("reset");
            $("#modalRemoveClusterNode").modal("hide");

            reloadAdminClusterView(responseJSON);

            showAlert("success", "Node Removed!", "Cluster node was removed successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalRemoveClusterNode").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divRemoveClusterNodeAlert
    });
}

function showPromoteToPrimaryClusterNodeModal(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var nodeName = mnuItem.attr("data-node-name");

    $("#lblPromoteToPrimaryClusterNodeName").text(nodeName);
    hideAlert($("#divPromoteToPrimaryClusterNodeAlert"));
    $("#chkPromoteToPrimaryClusterNodeForceDeletePrimary").prop("checked", false);
    $("#modalPromoteToPrimaryClusterNode").modal("show");
}

function promoteToPrimaryClusterNode(objBtn) {
    var divPromoteToPrimaryClusterNodeAlert = $("#divPromoteToPrimaryClusterNodeAlert");

    var forceDeletePrimary = $("#chkPromoteToPrimaryClusterNodeForceDeletePrimary").prop("checked");

    var node = $("#optAdminClusterNode").val();

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/admin/cluster/secondary/promote?token=" + sessionData.token + "&forceDeletePrimary=" + forceDeletePrimary + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            $("#modalPromoteToPrimaryClusterNode").modal("hide");
            btn.button("reset");

            reloadAdminClusterView(responseJSON);

            showAlert("success", "Promoted!", "The selected node was successfully promoted to Primary node in the Cluster.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalPromoteToPrimaryClusterNode").modal("hide");
            btn.button("reset");
            showPageLogin();
        },
        objAlertPlaceholder: divPromoteToPrimaryClusterNodeAlert
    });
}

function showInitializeClusterModal() {
    var divInitializeNewClusterAlert = $("#divInitializeNewClusterAlert");
    var divInitializeNewClusterLoader = $("#divInitializeNewClusterLoader");
    var divInitializeNewClusterView = $("#divInitializeNewClusterView");

    divInitializeNewClusterLoader.show();
    divInitializeNewClusterView.hide();

    $("#modalInitializeNewCluster").modal("show");

    HTTPRequest({
        url: "api/admin/cluster/state?token=" + sessionData.token + "&includeServerIpAddresses=true",
        success: function (responseJSON) {
            if (responseJSON.response.clusterInitialized) {
                showAlert("danger", "Error!", "Cluster is already initialized.", divInitializeNewClusterAlert);
                return;
            }

            $("#txtInitializeNewClusterDomain").val("");
            $("#txtInitializeNewClusterPrimaryNodeIpAddresses").val("");

            var optionsHtml = "<option></option>";

            for (var i = 0; i < responseJSON.response.serverIpAddresses.length; i++)
                optionsHtml += "<option>" + responseJSON.response.serverIpAddresses[i] + "</option>";

            $("#optInitializeNewClusterQuickIpAddresses").html(optionsHtml);

            divInitializeNewClusterLoader.hide();
            divInitializeNewClusterView.show();

            setTimeout(function () {
                $("#txtInitializeNewClusterDomain").trigger("focus");
            }, 1000);
        },
        invalidToken: function () {
            $("#modalInitializeNewCluster").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divInitializeNewClusterAlert,
        objLoaderPlaceholder: divInitializeNewClusterLoader
    });
}

function initializeNewCluster(objBtn) {
    var divInitializeNewClusterAlert = $("#divInitializeNewClusterAlert");

    var clusterDomain = $("#txtInitializeNewClusterDomain").val();
    if (clusterDomain === "") {
        showAlert("warning", "Missing!", "Please enter the Cluster domain name.", divInitializeNewClusterAlert);
        $("#txtInitializeNewClusterDomain").trigger("focus");
        return;
    }

    var primaryNodeIpAddresses = cleanTextList($("#txtInitializeNewClusterPrimaryNodeIpAddresses").val());
    if ((primaryNodeIpAddresses.length === 0) || (primaryNodeIpAddresses === ",")) {
        showAlert("warning", "Missing!", "Please enter a Primary node IP address.", divInitializeNewClusterAlert);
        $("#txtInitializeNewClusterPrimaryNodeIpAddresses").trigger("focus");
        return;
    }

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/admin/cluster/init?token=" + sessionData.token + "&clusterDomain=" + encodeURIComponent(clusterDomain) + "&primaryNodeIpAddresses=" + encodeURIComponent(primaryNodeIpAddresses),
        success: function (responseJSON) {
            $("#modalInitializeNewCluster").modal("hide");
            btn.button("reset");

            updateAdminClusterDataAndGui(responseJSON);
            reloadAdminClusterView(responseJSON);

            showAlert("success", "Cluster Initialized!", "A new cluster was initialized successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalInitializeNewCluster").modal("hide");
            btn.button("reset");
            showPageLogin();
        },
        objAlertPlaceholder: divInitializeNewClusterAlert
    });
}

function showInitializeJoinClusterModal() {
    var divInitializeJoinClusterAlert = $("#divInitializeJoinClusterAlert");
    var divInitializeJoinClusterLoader = $("#divInitializeJoinClusterLoader");
    var divInitializeJoinClusterView = $("#divInitializeJoinClusterView");

    divInitializeJoinClusterAlert.html("");
    divInitializeJoinClusterLoader.show();
    divInitializeJoinClusterView.hide();

    $("#modalInitializeJoinCluster").modal("show");

    HTTPRequest({
        url: "api/admin/cluster/state?token=" + sessionData.token + "&includeServerIpAddresses=true",
        success: function (responseJSON) {
            if (responseJSON.response.clusterInitialized) {
                showAlert("danger", "Error!", "Cluster is already initialized.", divInitializeJoinClusterAlert);
                return;
            }

            $("#txtInitializeJoinClusterSecondaryNodeIpAddresses").val("");

            var optionsHtml = "<option></option>";

            for (var i = 0; i < responseJSON.response.serverIpAddresses.length; i++)
                optionsHtml += "<option>" + responseJSON.response.serverIpAddresses[i] + "</option>";

            $("#optInitializeJoinClusterQuickIpAddresses").html(optionsHtml);

            $("#txtInitializeJoinClusterPrimaryNodeUrl").val("");
            $("#txtInitializeJoinClusterPrimaryNodeIpAddress").val("");
            $("#rdInitializeJoinClusterCertificateValidationDefault").prop("checked", true);
            $("#txtInitializeJoinClusterPrimaryNodeUsername").val("admin");
            $("#txtInitializeJoinClusterPrimaryNodePassword").prop("disabled", false);
            $("#txtInitializeJoinClusterPrimaryNodePassword").val("");
            $("#divInitializeJoinClusterPrimaryNode2faTotp").hide();
            $("#txtInitializeJoinClusterPrimaryNode2faTotp").val("");

            divInitializeJoinClusterLoader.hide();
            divInitializeJoinClusterView.show();

            setTimeout(function () {
                $("#txtInitializeJoinClusterSecondaryNodeIpAddresses").trigger("focus");
            }, 1000);
        },
        invalidToken: function () {
            $("#modalInitializeJoinCluster").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divInitializeJoinClusterAlert,
        objLoaderPlaceholder: divInitializeJoinClusterLoader
    });
}

function initializeJoinCluster(objBtn) {
    var divInitializeJoinClusterAlert = $("#divInitializeJoinClusterAlert");

    var secondaryNodeIpAddresses = cleanTextList($("#txtInitializeJoinClusterSecondaryNodeIpAddresses").val());
    if ((secondaryNodeIpAddresses.length === 0) || (secondaryNodeIpAddresses === ",")) {
        showAlert("warning", "Missing!", "Please select a Secondary node IP address.", divInitializeJoinClusterAlert);
        $("#txtInitializeJoinClusterSecondaryNodeIpAddresses").trigger("focus");
        return;
    }

    var primaryNodeUrl = $("#txtInitializeJoinClusterPrimaryNodeUrl").val();
    if (primaryNodeUrl === "") {
        showAlert("warning", "Missing!", "Please enter the Primary node URL.", divInitializeJoinClusterAlert);
        $("#txtInitializeJoinClusterPrimaryNodeUrl").trigger("focus");
        return;
    }

    var primaryNodeIpAddress = $("#txtInitializeJoinClusterPrimaryNodeIpAddress").val();
    var ignoreCertificateErrors = $("input[name=rdInitializeJoinClusterCertificateValidation]:checked").val();

    var primaryNodeUsername = $("#txtInitializeJoinClusterPrimaryNodeUsername").val();
    if (primaryNodeUsername === "") {
        showAlert("warning", "Missing!", "Please enter the Primary node admin username.", divInitializeJoinClusterAlert);
        $("#txtInitializeJoinClusterPrimaryNodeUsername").trigger("focus");
        return;
    }

    var primaryNodePassword = $("#txtInitializeJoinClusterPrimaryNodePassword").val();
    if (primaryNodePassword === "") {
        showAlert("warning", "Missing!", "Please enter the Primary node admin password.", divInitializeJoinClusterAlert);
        $("#txtInitializeJoinClusterPrimaryNodePassword").trigger("focus");
        return;
    }

    var primaryNodeTotp = $("#txtInitializeJoinClusterPrimaryNode2faTotp").val();
    if ($("#divInitializeJoinClusterPrimaryNode2faTotp").is(":visible")) {
        if (primaryNodeTotp === "") {
            showAlert("warning", "Missing!", "Please enter the Primary node admin user's OTP.", divInitializeJoinClusterAlert);
            $("#txtInitializeJoinClusterPrimaryNode2faTotp").trigger("focus");
            return;
        }
    }

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/admin/cluster/initJoin?token=" + sessionData.token + "&secondaryNodeIpAddresses=" + encodeURIComponent(secondaryNodeIpAddresses)
            + "&primaryNodeUrl=" + encodeURIComponent(primaryNodeUrl) + "&primaryNodeIpAddress=" + encodeURIComponent(primaryNodeIpAddress) + "&ignoreCertificateErrors=" + ignoreCertificateErrors
            + "&primaryNodeUsername=" + encodeURIComponent(primaryNodeUsername) + "&primaryNodePassword=" + encodeURIComponent(primaryNodePassword) + "&primaryNodeTotp=" + encodeURIComponent(primaryNodeTotp),
        success: function (responseJSON) {
            $("#modalInitializeJoinCluster").modal("hide");
            btn.button("reset");

            updateAdminClusterDataAndGui(responseJSON);
            reloadAdminClusterView(responseJSON);

            showAlert("success", "Joined Cluster!", "Joined the cluster successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalInitializeJoinCluster").modal("hide");
            btn.button("reset");
            showPageLogin();
        },
        twoFactorAuthRequired: function () {
            btn.button("reset");

            $("#txtInitializeJoinClusterPrimaryNodePassword").prop("disabled", true);
            $("#divInitializeJoinClusterPrimaryNode2faTotp").show();
            $("#txtInitializeJoinClusterPrimaryNode2faTotp").trigger("focus");
        },
        objAlertPlaceholder: divInitializeJoinClusterAlert
    });
}

function resyncCluster(objBtn) {
    if (!confirm("The resync Cluster action will initiate a full config transfer from the Primary node. You will need to check the logs to confirm if the resync action was successful.\r\n\r\nAre you sure you want to resync the Cluster config?"))
        return;

    var node = $("#optAdminClusterNode").val();

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/admin/cluster/secondary/resync?token=" + sessionData.token + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            btn.button("reset");
            showAlert("success", "Resync Triggered!", "A full config resync was triggered successfully. Please check the Logs for confirmation.");
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

function showClusterOptionsModal() {
    var divClusterOptionsAlert = $("#divClusterOptionsAlert");
    var divClusterOptionsLoader = $("#divClusterOptionsLoader");
    var divClusterOptionsView = $("#divClusterOptionsView");

    divClusterOptionsLoader.show();
    divClusterOptionsView.hide();

    var node = $("#optAdminClusterNode").val();

    $("#modalClusterOptions").modal("show");

    HTTPRequest({
        url: "api/admin/cluster/state?token=" + sessionData.token + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            var selfNodeType;

            for (var i = 0; i < responseJSON.response.clusterNodes.length; i++) {
                if (responseJSON.response.clusterNodes[i].state == "Self") {
                    selfNodeType = responseJSON.response.clusterNodes[i].type;
                    break;
                }
            }

            var isPrimaryNode = selfNodeType == "Primary";

            $("#txtClusterOptionsHeartbeatRefreshIntervalSeconds").attr("disabled", !isPrimaryNode);
            $("#txtClusterOptionsHeartbeatRetryIntervalSeconds").attr("disabled", !isPrimaryNode);
            $("#txtClusterOptionsConfigRefreshIntervalSeconds").attr("disabled", !isPrimaryNode);
            $("#txtClusterOptionsConfigRetryIntervalSeconds").attr("disabled", !isPrimaryNode);

            if (isPrimaryNode)
                $("#btnClusterOptionsSave").show();
            else
                $("#btnClusterOptionsSave").hide();

            $("#txtClusterOptionsClusterDomain").val(responseJSON.response.clusterDomain);
            $("#txtClusterOptionsHeartbeatRefreshIntervalSeconds").val(responseJSON.response.heartbeatRefreshIntervalSeconds);
            $("#txtClusterOptionsHeartbeatRetryIntervalSeconds").val(responseJSON.response.heartbeatRetryIntervalSeconds);
            $("#txtClusterOptionsConfigRefreshIntervalSeconds").val(responseJSON.response.configRefreshIntervalSeconds);
            $("#txtClusterOptionsConfigRetryIntervalSeconds").val(responseJSON.response.configRetryIntervalSeconds);

            divClusterOptionsLoader.hide();
            divClusterOptionsView.show();

            setTimeout(function () {
                $("#txtClusterOptionsHeartbeatRefreshIntervalSeconds").trigger("focus");
            }, 1000);
        },
        invalidToken: function () {
            $("#modalClusterOptions").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divClusterOptionsAlert,
        objLoaderPlaceholder: divClusterOptionsLoader
    });
}

function saveClusterOptions(objBtn) {
    var divClusterOptionsAlert = $("#divClusterOptionsAlert");

    var heartbeatRefreshIntervalSeconds = $("#txtClusterOptionsHeartbeatRefreshIntervalSeconds").val();
    if (heartbeatRefreshIntervalSeconds === "") {
        showAlert("warning", "Missing!", "Please enter a value for Heartbeat Refresh Interval.", divClusterOptionsAlert);
        $("#txtClusterOptionsHeartbeatRefreshIntervalSeconds").trigger("focus");
        return;
    }

    var heartbeatRetryIntervalSeconds = $("#txtClusterOptionsHeartbeatRetryIntervalSeconds").val();
    if (heartbeatRetryIntervalSeconds === "") {
        showAlert("warning", "Missing!", "Please enter a value for Heartbeat Retry Interval.", divClusterOptionsAlert);
        $("#txtClusterOptionsHeartbeatRetryIntervalSeconds").trigger("focus");
        return;
    }

    var configRefreshIntervalSeconds = $("#txtClusterOptionsConfigRefreshIntervalSeconds").val();
    if (configRefreshIntervalSeconds === "") {
        showAlert("warning", "Missing!", "Please enter a value for Config Refresh Interval.", divClusterOptionsAlert);
        $("#txtClusterOptionsConfigRefreshIntervalSeconds").trigger("focus");
        return;
    }

    var configRetryIntervalSeconds = $("#txtClusterOptionsConfigRetryIntervalSeconds").val();
    if (configRetryIntervalSeconds === "") {
        showAlert("warning", "Missing!", "Please enter a value for Config Retry Interval.", divClusterOptionsAlert);
        $("#txtClusterOptionsConfigRetryIntervalSeconds").trigger("focus");
        return;
    }

    var node = $("#optAdminClusterNode").val();

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/admin/cluster/primary/setOptions?token=" + sessionData.token
            + "&heartbeatRefreshIntervalSeconds=" + heartbeatRefreshIntervalSeconds + "&heartbeatRetryIntervalSeconds=" + heartbeatRetryIntervalSeconds
            + "&configRefreshIntervalSeconds=" + configRefreshIntervalSeconds + "&configRetryIntervalSeconds=" + configRetryIntervalSeconds
            + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            $("#modalClusterOptions").modal("hide");
            btn.button("reset");

            showAlert("success", "Options Saved!", "The Cluster options were saved successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalClusterOptions").modal("hide");
            btn.button("reset");
            showPageLogin();
        },
        objAlertPlaceholder: divClusterOptionsAlert,
    });
}

function showLeaveClusterModal() {
    hideAlert($("#divLeaveClusterAlert"));
    $("#chkLeaveClusterForceLeave").prop("checked", false);
    $("#modalLeaveCluster").modal("show");
}

function leaveCluster(objBtn) {
    var divLeaveClusterAlert = $("#divLeaveClusterAlert");

    var forceLeave = $("#chkLeaveClusterForceLeave").prop("checked");

    var node = $("#optAdminClusterNode").val();

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/admin/cluster/secondary/leave?token=" + sessionData.token + "&forceLeave=" + forceLeave + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            $("#modalLeaveCluster").modal("hide");
            btn.button("reset");

            updateAdminClusterDataAndGui(responseJSON);
            reloadAdminClusterView(responseJSON);

            showAlert("success", "Left Cluster!", "Left the Cluster successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalLeaveCluster").modal("hide");
            btn.button("reset");
            showPageLogin();
        },
        objAlertPlaceholder: divLeaveClusterAlert
    });
}

function showDeleteClusterModal() {
    hideAlert($("#divDeleteClusterAlert"));
    $("#chkDeleteClusterForceDelete").prop("checked", false);
    $("#modalDeleteCluster").modal("show");
}

function deleteCluster(objBtn) {
    var divDeleteClusterAlert = $("#divDeleteClusterAlert");

    var forceDelete = $("#chkDeleteClusterForceDelete").prop("checked");

    var node = $("#optAdminClusterNode").val();

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/admin/cluster/primary/delete?token=" + sessionData.token + "&forceDelete=" + forceDelete + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            $("#modalDeleteCluster").modal("hide");
            btn.button("reset");

            updateAdminClusterDataAndGui(responseJSON);
            reloadAdminClusterView(responseJSON);

            showAlert("success", "Cluster Deleted!", "Cluster was deleted successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalDeleteCluster").modal("hide");
            btn.button("reset");
            showPageLogin();
        },
        objAlertPlaceholder: divDeleteClusterAlert
    });
}

function getPrimaryClusterNodeName() {
    if (sessionData.info.clusterInitialized) {
        for (var i = 0; i < sessionData.info.clusterNodes.length; i++) {
            if (sessionData.info.clusterNodes[i].type == "Primary")
                return sessionData.info.clusterNodes[i].name;
        }
    }

    return "";
}

function updateAllClusterNodeDropDowns() {
    updateClusterNodeDropDown($("#optDashboardClusterNode"), true);
    updateClusterNodeDropDown($("#optZonesClusterNode"));
    updateClusterNodeDropDown($("#optEditZoneClusterNode"));
    updateClusterNodeDropDown($("#optCachedZonesClusterNode"));
    updateClusterNodeDropDown($("#optDnsClientClusterNode"));
    updateClusterNodeDropDown($("#optSettingsClusterNode"), true);
    updateClusterNodeDropDown($("#optDhcpClusterNode"));
    updateClusterNodeDropDown($("#optAdminSessionsClusterNode"));
    updateClusterNodeDropDown($("#optAdminClusterNode"));
    updateClusterNodeDropDown($("#optLogsClusterNode"));
}

function updateClusterNodeDropDown(optClusterNode, addClusterNode, selectedNode) {
    if (sessionData.info.clusterInitialized) {
        if (selectedNode == null)
            selectedNode = optClusterNode.val();

        var html = "";

        if (addClusterNode)
            html += "<option value=\"cluster\">Cluster</option>";

        for (var i = 0; i < sessionData.info.clusterNodes.length; i++)
            html += "<option value=\"" + htmlEncode(sessionData.info.clusterNodes[i].name) + "\">" + htmlEncode(sessionData.info.clusterNodes[i].name) + " (" + htmlEncode(sessionData.info.clusterNodes[i].type.toLowerCase()) + ")" + "</option>";

        optClusterNode.html(html);

        if ((selectedNode == null) || (selectedNode == "")) {
            if (addClusterNode)
                selectedNode = "cluster";
            else
                selectedNode = sessionData.info.dnsServerDomain;
        }

        optClusterNode.val(selectedNode);

        if ((optClusterNode.val() == null) && (sessionData.info.clusterNodes.length > 0))
            optClusterNode.val(sessionData.info.clusterNodes[0].name);

        optClusterNode.show();
    }
    else {
        optClusterNode.hide();
        optClusterNode.html("<option></option>");
        optClusterNode.val("");
    }
}
