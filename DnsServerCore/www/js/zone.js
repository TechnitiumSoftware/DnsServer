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

var zoneOptionsAvailableTsigKeyNames;
var editZoneInfo;
var editZoneRecords;
var editZoneFilteredRecords;

$(function () {
    $("input[type=radio][name=rdAddZoneType]").on("change", function () {
        $("#txtAddZone").prop("disabled", false);
        $("#divAddZoneCatalogZone").hide();
        $("#divAddZoneInitializeForwarder").hide();
        $("#divAddZoneImportZoneFile").hide();
        $("#divAddZoneUseSoaSerialDateScheme").hide();
        $("#divAddZonePrimaryNameServerAddresses").hide();
        $("#lblAddZonePrimaryNameServerAddresses").text("Primary Name Server Addresses (Optional)");
        $("#divAddZonePrimaryNameServerAddressesInfo").text("Enter the primary name server addresses to sync the zone from. When unspecified, the SOA Primary Name Server will be resolved and used.");
        $("#divAddZoneZoneTransferProtocol").hide();
        $("#divAddZoneTsigKeyName").hide();
        $("#divAddZoneValidateZone").hide();
        $("#divAddZoneForwarderProtocol").hide();
        $("#divAddZoneForwarder").hide();
        $("#divAddZoneForwarderDnssecValidation").hide();
        $("#divAddZoneForwarderProxy").hide();

        var zoneType = $('input[name=rdAddZoneType]:checked').val();
        switch (zoneType) {
            case "Primary":
                if ($("#optAddZoneCatalogZoneName").attr("hasItems") == "true")
                    $("#divAddZoneCatalogZone").show();

                $("#divAddZoneImportZoneFile").show();
                $("#divAddZoneUseSoaSerialDateScheme").show();
                break;

            case "Secondary":
                $("#divAddZonePrimaryNameServerAddresses").show();
                $("#divAddZoneZoneTransferProtocol").show();
                $("#divAddZoneTsigKeyName").show();
                $("#divAddZoneValidateZone").show();

                loadTsigKeyNames($("#optAddZoneTsigKeyName"), null, $("#divAddZoneAlert"));
                break;

            case "Stub":
                if ($("#optAddZoneCatalogZoneName").attr("hasItems") == "true")
                    $("#divAddZoneCatalogZone").show();

                $("#divAddZonePrimaryNameServerAddresses").show();
                break;

            case "Forwarder":
                if ($("#optAddZoneCatalogZoneName").attr("hasItems") == "true")
                    $("#divAddZoneCatalogZone").show();

                $("#divAddZoneInitializeForwarder").show();

                var initializeForwarder = $("#chkAddZoneInitializeForwarder").prop("checked");

                if (initializeForwarder) {
                    $("#divAddZoneImportZoneFile").hide();

                    $("#divAddZoneForwarderProtocol").show();
                    $("#divAddZoneForwarder").show();
                    $("#divAddZoneForwarderDnssecValidation").show();
                    $("#divAddZoneForwarderProxy").show();
                } else {
                    $("#divAddZoneImportZoneFile").show();

                    $("#divAddZoneForwarderProtocol").hide();
                    $("#divAddZoneForwarder").hide();
                    $("#divAddZoneForwarderDnssecValidation").hide();
                    $("#divAddZoneForwarderProxy").hide();
                }

                break;

            case "SecondaryForwarder":
            case "SecondaryCatalog":
                $("#lblAddZonePrimaryNameServerAddresses").text("Primary Name Server Addresses");
                $("#divAddZonePrimaryNameServerAddressesInfo").text("Enter the primary name server addresses to sync the zone from.");
                $("#divAddZonePrimaryNameServerAddresses").show();
                $("#divAddZoneZoneTransferProtocol").show();
                $("#divAddZoneTsigKeyName").show();

                loadTsigKeyNames($("#optAddZoneTsigKeyName"), null, $("#divAddZoneAlert"));
                break;

            case "SecondaryRoot":
                $("#txtAddZone").prop("disabled", true);
                $("#txtAddZone").val(".");
                break;
        }
    });

    $("#chkAddZoneInitializeForwarder").on("click", function () {
        var initializeForwarder = $("#chkAddZoneInitializeForwarder").prop("checked");

        if (initializeForwarder) {
            $("#divAddZoneImportZoneFile").hide();

            $("#divAddZoneForwarderProtocol").show();
            $("#divAddZoneForwarder").show();
            $("#divAddZoneForwarderDnssecValidation").show();
            $("#divAddZoneForwarderProxy").show();
        } else {
            $("#divAddZoneImportZoneFile").show();

            $("#divAddZoneForwarderProtocol").hide();
            $("#divAddZoneForwarder").hide();
            $("#divAddZoneForwarderDnssecValidation").hide();
            $("#divAddZoneForwarderProxy").hide();
        }
    });

    $("input[type=radio][name=rdAddZoneForwarderProtocol]").on("change", function () {
        var protocol = $('input[name=rdAddZoneForwarderProtocol]:checked').val();
        switch (protocol) {
            case "Udp":
            case "Tcp":
                $("#txtAddZoneForwarder").attr("placeholder", "8.8.8.8 or [2620:fe::10]")
                break;

            case "Tls":
            case "Quic":
                $("#txtAddZoneForwarder").attr("placeholder", "dns.quad9.net (9.9.9.9:853)")
                break;

            case "Https":
                $("#txtAddZoneForwarder").attr("placeholder", "https://cloudflare-dns.com/dns-query (1.1.1.1)")
                break;
        }
    });

    $("input[type=radio][name=rdAddZoneForwarderProxyType]").on("change", function () {
        var proxyType = $('input[name=rdAddZoneForwarderProxyType]:checked').val();
        var disabled = (proxyType === "NoProxy") || (proxyType === "DefaultProxy");

        $("#txtAddZoneForwarderProxyAddress").prop("disabled", disabled);
        $("#txtAddZoneForwarderProxyPort").prop("disabled", disabled);
        $("#txtAddZoneForwarderProxyUsername").prop("disabled", disabled);
        $("#txtAddZoneForwarderProxyPassword").prop("disabled", disabled);
    });

    $("#txtEditZoneFilterName").on("input", function () {
        editZoneFilteredRecords = null; //to evaluate filters again
    });

    $("#txtEditZoneFilterType").on("input", function () {
        editZoneFilteredRecords = null; //to evaluate filters again
    });

    $("input[type=radio][name=rdImportZoneType]").on("change", function () {
        var rdImportZoneType = $("input[name=rdImportZoneType]:checked").val();
        switch (rdImportZoneType) {
            case "File":
                $("#divImportZoneFile").show();
                $("#divImportZoneTextEditor").hide();
                break;

            case "Text":
                $("#divImportZoneFile").hide();
                $("#divImportZoneTextEditor").show();
                break;
        }
    });

    $("#optZoneOptionsCatalogZoneName").on("change", function () {
        var catalog = $("#optZoneOptionsCatalogZoneName").val();
        if (catalog === "") {
            $("#chkZoneOptionsCatalogOverrideQueryAccess").prop("checked", false);
            $("#chkZoneOptionsCatalogOverrideZoneTransfer").prop("checked", false);
            $("#chkZoneOptionsCatalogOverrideNotify").prop("checked", false);

            $("#chkZoneOptionsCatalogOverrideQueryAccess").prop("disabled", true);
            $("#chkZoneOptionsCatalogOverrideZoneTransfer").prop("disabled", true);
            $("#chkZoneOptionsCatalogOverrideNotify").prop("disabled", true);

            switch ($("#lblZoneOptionsZoneName").attr("data-zone-type")) {
                case "Primary":
                case "Forwarder":
                    $("#tabListZoneOptionsQueryAccess").show();
                    $("#tabListZoneOptionsZoneTranfer").show();
                    $("#tabListZoneOptionsNotify").show();
                    break;

                case "Stub":
                    $("#tabListZoneOptionsQueryAccess").show();
                    break;
            }
        }
        else {
            $("#chkZoneOptionsCatalogOverrideQueryAccess").prop("checked", false);
            $("#chkZoneOptionsCatalogOverrideZoneTransfer").prop("checked", false);
            $("#chkZoneOptionsCatalogOverrideNotify").prop("checked", false);

            switch ($("#lblZoneOptionsZoneName").attr("data-zone-type")) {
                case "Primary":
                case "Forwarder":
                    $("#chkZoneOptionsCatalogOverrideQueryAccess").prop("disabled", false);
                    $("#chkZoneOptionsCatalogOverrideZoneTransfer").prop("disabled", false);
                    $("#chkZoneOptionsCatalogOverrideNotify").prop("disabled", false);
                    break;

                case "Stub":
                    $("#chkZoneOptionsCatalogOverrideQueryAccess").prop("disabled", false);
                    break;
            }

            $("#tabListZoneOptionsQueryAccess").hide();
            $("#tabListZoneOptionsZoneTranfer").hide();
            $("#tabListZoneOptionsNotify").hide();
        }
    });

    $("#chkZoneOptionsCatalogOverrideQueryAccess").on("click", function () {
        var checked = $("#chkZoneOptionsCatalogOverrideQueryAccess").prop("checked");

        if (checked)
            $("#tabListZoneOptionsQueryAccess").show();
        else
            $("#tabListZoneOptionsQueryAccess").hide();
    });

    $("#chkZoneOptionsCatalogOverrideZoneTransfer").on("click", function () {
        var checked = $("#chkZoneOptionsCatalogOverrideZoneTransfer").prop("checked");

        if (checked)
            $("#tabListZoneOptionsZoneTranfer").show();
        else
            $("#tabListZoneOptionsZoneTranfer").hide();
    });

    $("#chkZoneOptionsCatalogOverrideNotify").on("click", function () {
        var checked = $("#chkZoneOptionsCatalogOverrideNotify").prop("checked");

        if (checked)
            $("#tabListZoneOptionsNotify").show();
        else
            $("#tabListZoneOptionsNotify").hide();
    });

    $("input[type=radio][name=rdQueryAccess]").on("change", function () {
        var queryAccess = $("input[name=rdQueryAccess]:checked").val();
        switch (queryAccess) {
            case "UseSpecifiedNetworkACL":
            case "AllowZoneNameServersAndUseSpecifiedNetworkACL":
                $("#txtQueryAccessNetworkACL").prop("disabled", false);
                break;

            default:
                $("#txtQueryAccessNetworkACL").prop("disabled", true);
                break;
        }
    });

    $("input[type=radio][name=rdZoneTransfer]").on("change", function () {
        var zoneTransfer = $('input[name=rdZoneTransfer]:checked').val();
        switch (zoneTransfer) {
            case "UseSpecifiedNetworkACL":
            case "AllowZoneNameServersAndUseSpecifiedNetworkACL":
                $("#txtZoneTransferNetworkACL").prop("disabled", false);
                break;

            default:
                $("#txtZoneTransferNetworkACL").prop("disabled", true);
                break;
        }
    });

    $("input[type=radio][name=rdZoneNotify]").on("change", function () {
        var zoneNotify = $('input[name=rdZoneNotify]:checked').val();
        switch (zoneNotify) {
            case "SpecifiedNameServers":
            case "BothZoneAndSpecifiedNameServers":
                $("#txtZoneNotifyNameServers").prop("disabled", false);
                $("#txtZoneNotifySecondaryCatalogNameServers").prop("disabled", true);
                break;

            case "SeparateNameServersForCatalogAndMemberZones":
                $("#txtZoneNotifyNameServers").prop("disabled", false);
                $("#txtZoneNotifySecondaryCatalogNameServers").prop("disabled", false);
                break;

            default:
                $("#txtZoneNotifyNameServers").prop("disabled", true);
                $("#txtZoneNotifySecondaryCatalogNameServers").prop("disabled", true);
                break;
        }
    });

    $("input[type=radio][name=rdDynamicUpdate]").on("change", function () {
        var dynamicUpdate = $('input[name=rdDynamicUpdate]:checked').val();
        switch (dynamicUpdate) {
            case "UseSpecifiedNetworkACL":
            case "AllowZoneNameServersAndUseSpecifiedNetworkACL":
                $("#txtDynamicUpdateNetworkACL").prop("disabled", false);
                break;

            default:
                $("#txtDynamicUpdateNetworkACL").prop("disabled", true);
                break;
        }
    });

    $("input[type=radio][name=rdDnssecSignZoneAlgorithm]").on("change", function () {
        var algorithm = $("input[name=rdDnssecSignZoneAlgorithm]:checked").val();
        switch (algorithm) {
            case "RSA":
                $("#divDnssecSignZoneRsaParameters").show();
                $("#divDnssecSignZoneEcdsaParameters").hide();
                $("#divDnssecSignZoneEddsaParameters").hide();

                if ($("input[name=rdDnssecSignZoneKskGeneration]:checked").val() === "Automatic")
                    $("#divDnssecSignZoneRsaKskKeySize").show();
                else
                    $("#divDnssecSignZoneRsaKskKeySize").hide();

                if ($("input[name=rdDnssecSignZoneZskGeneration]:checked").val() === "Automatic")
                    $("#divDnssecSignZoneRsaZskKeySize").show();
                else
                    $("#divDnssecSignZoneRsaZskKeySize").hide();

                break;

            case "ECDSA":
                $("#divDnssecSignZoneRsaParameters").hide();
                $("#divDnssecSignZoneEcdsaParameters").show();
                $("#divDnssecSignZoneEddsaParameters").hide();

                $("#divDnssecSignZoneRsaKskKeySize").hide();
                $("#divDnssecSignZoneRsaZskKeySize").hide();
                break;

            case "EDDSA":
                $("#divDnssecSignZoneRsaParameters").hide();
                $("#divDnssecSignZoneEcdsaParameters").hide();
                $("#divDnssecSignZoneEddsaParameters").show();

                $("#divDnssecSignZoneRsaKskKeySize").hide();
                $("#divDnssecSignZoneRsaZskKeySize").hide();
                break;
        }
    });

    $("input[type=radio][name=rdDnssecSignZoneKskGeneration]").on("change", function () {
        var rdDnssecSignZoneKskGeneration = $("input[name=rdDnssecSignZoneKskGeneration]:checked").val();
        switch (rdDnssecSignZoneKskGeneration) {
            case "Automatic":
                if ($("input[name=rdDnssecSignZoneAlgorithm]:checked").val() === "RSA")
                    $("#divDnssecSignZoneRsaKskKeySize").show();
                else
                    $("#divDnssecSignZoneRsaKskKeySize").hide();

                $("#divDnssecSignZonePemKskPrivateKey").hide();
                break;

            case "UseSpecified":
                $("#divDnssecSignZoneRsaKskKeySize").hide();
                $("#divDnssecSignZonePemKskPrivateKey").show();
                break;
        }

        $("#txtDnssecSignZonePemKskPrivateKey").val("");
    });

    $("input[type=radio][name=rdDnssecSignZoneZskGeneration]").on("change", function () {
        var rdDnssecSignZoneZskGeneration = $("input[name=rdDnssecSignZoneZskGeneration]:checked").val();
        switch (rdDnssecSignZoneZskGeneration) {
            case "Automatic":
                if ($("input[name=rdDnssecSignZoneAlgorithm]:checked").val() === "RSA")
                    $("#divDnssecSignZoneRsaZskKeySize").show();
                else
                    $("#divDnssecSignZoneRsaZskKeySize").hide();

                $("#divDnssecSignZonePemZskPrivateKey").hide();
                $("#txtDnssecSignZoneZskAutoRollover").val("30");
                break;

            case "UseSpecified":
                $("#divDnssecSignZoneRsaZskKeySize").hide();
                $("#divDnssecSignZonePemZskPrivateKey").show();
                $("#txtDnssecSignZoneZskAutoRollover").val("0");
                break;
        }

        $("#txtDnssecSignZonePemZskPrivateKey").val("");
    });

    $("input[type=radio][name=rdDnssecSignZoneNxProof]").on("change", function () {
        var nxProof = $("input[name=rdDnssecSignZoneNxProof]:checked").val();
        switch (nxProof) {
            case "NSEC":
                $("#divDnssecSignZoneNSEC3Parameters").hide();
                break;

            case "NSEC3":
                $("#divDnssecSignZoneNSEC3Parameters").show();
                break;
        }
    });

    $("#optDnssecPropertiesAddKeyKeyType").on("change", function () {
        var keyType = $("#optDnssecPropertiesAddKeyKeyType").val();
        switch (keyType) {
            case "ZoneSigningKey":
                $("#divDnssecPropertiesAddKeyAutomaticRollover").show();

                if ($("input[name=rdDnssecPropertiesKeyGeneration]:checked").val() === "Automatic")
                    $("#txtDnssecPropertiesAddKeyAutomaticRollover").val(30);
                else
                    $("#txtDnssecPropertiesAddKeyAutomaticRollover").val(0);

                break;

            default:
                $("#divDnssecPropertiesAddKeyAutomaticRollover").hide();
                $("#txtDnssecPropertiesAddKeyAutomaticRollover").val(0);
                break;
        }
    });

    $("#optDnssecPropertiesAddKeyAlgorithm").on("change", function () {
        var algorithm = $("#optDnssecPropertiesAddKeyAlgorithm").val();
        switch (algorithm) {
            case "RSA":
                $("#divDnssecPropertiesAddKeyRsaParameters").show();
                $("#divDnssecPropertiesAddKeyEcdsaParameters").hide();
                $("#divDnssecPropertiesAddKeyEddsaParameters").hide();

                if ($("input[name=rdDnssecPropertiesKeyGeneration]:checked").val() === "Automatic")
                    $("#divDnssecPropertiesAddKeyRsaKeySize").show();
                else
                    $("#divDnssecPropertiesAddKeyRsaKeySize").hide();

                break;

            case "ECDSA":
                $("#divDnssecPropertiesAddKeyRsaParameters").hide();
                $("#divDnssecPropertiesAddKeyEcdsaParameters").show();
                $("#divDnssecPropertiesAddKeyEddsaParameters").hide();

                $("#divDnssecPropertiesAddKeyRsaKeySize").hide();
                break;

            case "EDDSA":
                $("#divDnssecPropertiesAddKeyRsaParameters").hide();
                $("#divDnssecPropertiesAddKeyEcdsaParameters").hide();
                $("#divDnssecPropertiesAddKeyEddsaParameters").show();

                $("#divDnssecPropertiesAddKeyRsaKeySize").hide();
                break;
        }
    });

    $("input[type=radio][name=rdDnssecPropertiesKeyGeneration]").on("change", function () {
        var rdDnssecPropertiesKeyGeneration = $("input[name=rdDnssecPropertiesKeyGeneration]:checked").val();
        switch (rdDnssecPropertiesKeyGeneration) {
            case "Automatic":
                if ($("#optDnssecPropertiesAddKeyAlgorithm").val() == "RSA")
                    $("#divDnssecPropertiesAddKeyRsaKeySize").show();
                else
                    $("#divDnssecPropertiesAddKeyRsaKeySize").hide();

                $("#divDnssecPropertiesPemPrivateKey").hide();

                var keyType = $("#optDnssecPropertiesAddKeyKeyType").val();
                if (keyType == "ZoneSigningKey")
                    $("#txtDnssecPropertiesAddKeyAutomaticRollover").val(30);
                else
                    $("#txtDnssecPropertiesAddKeyAutomaticRollover").val(0);

                break;

            case "UseSpecified":
                $("#divDnssecPropertiesAddKeyRsaKeySize").hide();
                $("#divDnssecPropertiesPemPrivateKey").show();
                $("#txtDnssecPropertiesAddKeyAutomaticRollover").val(0);
                break;
        }

        $("#txtDnssecPropertiesPemPrivateKey").val("");
    });

    $("input[type=radio][name=rdDnssecPropertiesNxProof]").on("change", function () {
        var nxProof = $("input[name=rdDnssecPropertiesNxProof]:checked").val();
        switch (nxProof) {
            case "NSEC":
                $("#divDnssecPropertiesNSEC3Parameters").hide();
                break;

            case "NSEC3":
                $("#divDnssecPropertiesNSEC3Parameters").show();
                break;
        }
    });

    $("#chkAddEditRecordDataPtr").on("click", function () {
        var addPtrRecord = $("#chkAddEditRecordDataPtr").prop('checked');
        $("#chkAddEditRecordDataCreatePtrZone").prop('disabled', !addPtrRecord);
    });

    $("#chkAddEditRecordDataTxtSplitText").on("click", function () {
        var splitText = $("#chkAddEditRecordDataTxtSplitText").prop("checked");
        if (!splitText) {
            var text = $("#txtAddEditRecordDataTxt").val();
            text = text.replace(/\n/g, "");
            $("#txtAddEditRecordDataTxt").val(text);
        }
    });

    $("input[type=radio][name=rdAddEditRecordDataForwarderProtocol]").on("change", updateAddEditFormForwarderPlaceholder);

    $("input[type=radio][name=rdAddEditRecordDataForwarderProxyType]").on("change", updateAddEditFormForwarderProxyType);

    $("#optAddEditRecordDataAppName").on("change", function () {
        if (appsList == null)
            return;

        var appName = $("#optAddEditRecordDataAppName").val();
        var optClassPaths = "<option></option>";

        for (var i = 0; i < appsList.length; i++) {
            if (appsList[i].name == appName) {
                for (var j = 0; j < appsList[i].dnsApps.length; j++) {
                    if (appsList[i].dnsApps[j].isAppRecordRequestHandler)
                        optClassPaths += "<option>" + appsList[i].dnsApps[j].classPath + "</option>";
                }

                break;
            }
        }

        $("#optAddEditRecordDataClassPath").html(optClassPaths);
        $("#txtAddEditRecordDataData").val("");
    });

    $("#optAddEditRecordDataClassPath").on("change", function () {
        if (appsList == null)
            return;

        var appName = $("#optAddEditRecordDataAppName").val();
        var classPath = $("#optAddEditRecordDataClassPath").val();

        for (var i = 0; i < appsList.length; i++) {
            if (appsList[i].name == appName) {
                for (var j = 0; j < appsList[i].dnsApps.length; j++) {
                    if (appsList[i].dnsApps[j].classPath == classPath) {
                        $("#txtAddEditRecordDataData").val(appsList[i].dnsApps[j].recordDataTemplate);
                        return;
                    }
                }
            }
        }

        $("#txtAddEditRecordDataData").val("");
    });

    $("#optZoneOptionsQuickTsigKeyNames").on("change", function () {
        var selectedOption = $("#optZoneOptionsQuickTsigKeyNames").val();
        switch (selectedOption) {
            case "blank":
                break;

            case "none":
                $("#txtZoneOptionsZoneTransferTsigKeyNames").val("");
                break;

            default:
                var existingList = $("#txtZoneOptionsZoneTransferTsigKeyNames").val();

                if (existingList.indexOf(selectedOption) < 0) {
                    existingList += selectedOption + "\n";
                    $("#txtZoneOptionsZoneTransferTsigKeyNames").val(existingList);
                }

                break;
        }
    });

    $("#optZonesPerPage").on("change", function () {
        localStorage.setItem("optZonesPerPage", $("#optZonesPerPage").val());
    });

    var optZonesPerPage = localStorage.getItem("optZonesPerPage");
    if (optZonesPerPage != null)
        $("#optZonesPerPage").val(optZonesPerPage);

    $("#optEditZoneRecordsPerPage").on("change", function () {
        localStorage.setItem("optEditZoneRecordsPerPage", $("#optEditZoneRecordsPerPage").val());
    });

    var optEditZoneRecordsPerPage = localStorage.getItem("optEditZoneRecordsPerPage");
    if (optEditZoneRecordsPerPage != null)
        $("#optEditZoneRecordsPerPage").val(optEditZoneRecordsPerPage);

    $("#chkEditRecordDataSoaUseSerialDateScheme").on("click", function () {
        var useSerialDateScheme = $("#chkEditRecordDataSoaUseSerialDateScheme").prop("checked");

        $("#txtEditRecordDataSoaSerial").prop("disabled", useSerialDateScheme);
    });
});

function refreshZones(checkDisplay, pageNumber) {
    if (checkDisplay == null)
        checkDisplay = false;

    var divViewZones = $("#divViewZones");

    if (checkDisplay) {
        if (divViewZones.css("display") === "none")
            return;

        if (($("#tableZonesBody").html().length > 0) && !$("#mainPanelTabPaneZones").hasClass("active"))
            return;
    }

    if (pageNumber == null) {
        pageNumber = $("#txtZonesPageNumber").val();
        if (pageNumber == "")
            pageNumber = 1;
    }

    var zonesPerPage = Number($("#optZonesPerPage").val());
    if (zonesPerPage < 1)
        zonesPerPage = 10;

    var node = $("#optZonesClusterNode").val();

    var divViewZonesLoader = $("#divViewZonesLoader");
    var divEditZone = $("#divEditZone");

    divViewZones.hide();
    divEditZone.hide();
    divViewZonesLoader.show();

    HTTPRequest({
        url: "api/zones/list?token=" + sessionData.token + "&pageNumber=" + pageNumber + "&zonesPerPage=" + zonesPerPage + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            var zones = responseJSON.response.zones;
            var firstRowNumber = ((responseJSON.response.pageNumber - 1) * zonesPerPage) + 1;
            var lastRowNumber = firstRowNumber + (zones.length - 1);
            var tableHtmlRows = "";

            for (var i = 0; i < zones.length; i++) {
                var id = Math.floor(Math.random() * 10000);
                var name = zones[i].name;

                if (name === "")
                    name = ".";

                var type;
                if (zones[i].internal) {
                    type = "<span class=\"label label-default\">Internal</span>";
                }
                else {
                    switch (zones[i].type) {
                        case "SecondaryForwarder":
                            type = "<span class=\"label label-primary\">Secondary Forwarder</span>";
                            break;

                        case "SecondaryCatalog":
                            type = "<span class=\"label label-primary\">Secondary Catalog</span>";
                            break;

                        default:
                            type = "<span class=\"label label-primary\">" + zones[i].type + "</span>";
                            break;
                    }
                }

                var soaSerial = zones[i].soaSerial;
                if (soaSerial == null)
                    soaSerial = "&nbsp;";

                var dnssecStatus = "";

                switch (zones[i].dnssecStatus) {
                    case "SignedWithNSEC":
                    case "SignedWithNSEC3":
                        if (zones[i].hasDnssecPrivateKeys)
                            dnssecStatus = "<span class=\"label label-primary\">DNSSEC</span>";
                        else
                            dnssecStatus = "<span class=\"label label-default\">DNSSEC</span>";

                        break;
                }

                var status = "";

                if (zones[i].disabled)
                    status = "<span id=\"tdZoneStatus" + id + "\" class=\"label label-warning\">Disabled</span>";
                else if (zones[i].isExpired)
                    status = "<span id=\"tdZoneStatus" + id + "\" class=\"label label-danger\">Expired</span>";
                else if (zones[i].validationFailed)
                    status = "<span id=\"tdZoneStatus" + id + "\" class=\"label label-danger\">Validation Failed</span>";
                else if (zones[i].syncFailed)
                    status = "<span id=\"tdZoneStatus" + id + "\" class=\"label label-warning\">Sync Failed</span>";
                else if (zones[i].notifyFailed)
                    status = "<span id=\"tdZoneStatus" + id + "\" class=\"label label-warning\">Notify Failed</span>";
                else
                    status = "<span id=\"tdZoneStatus" + id + "\" class=\"label label-success\">Enabled</span>";

                var expiry = zones[i].expiry;
                if (expiry == null)
                    expiry = "&nbsp;";
                else
                    expiry = moment(expiry).local().format("YYYY-MM-DD HH:mm");

                var lastModified = zones[i].lastModified;
                if (lastModified == null)
                    lastModified = "&nbsp;";
                else
                    lastModified = moment(lastModified).local().format("YYYY-MM-DD HH:mm");

                var isReadOnlyZone = zones[i].internal;

                var showResyncMenu;

                switch (zones[i].type) {
                    case "Secondary":
                    case "SecondaryForwarder":
                    case "SecondaryCatalog":
                    case "Stub":
                        showResyncMenu = true;
                        break;

                    default:
                        showResyncMenu = false;
                        break;
                }

                var hideOptionsMenu;

                switch (zones[i].type) {
                    case "Primary":
                        hideOptionsMenu = zones[i].internal;
                        break;

                    case "Secondary":
                    case "SecondaryForwarder":
                    case "SecondaryCatalog":
                    case "Stub":
                    case "Forwarder":
                    case "Catalog":
                        hideOptionsMenu = false;
                        break;

                    default:
                        hideOptionsMenu = true;
                        break;
                }

                var nameTags;

                if (zones[i].catalog != null) {
                    nameTags = "<div><span id=\"tagZoneCatalogName" + id + "\" class=\"label label-default\">" + htmlEncode(zones[i].catalog) + "</span></div>";
                }
                else {
                    switch (zones[i].type) {
                        case "Catalog":
                        case "SecondaryCatalog":
                            nameTags = "<div><span id=\"tagZoneCatalogName" + id + "\" class=\"label label-info\">" + htmlEncode(name) + "</span></div>";
                            break;

                        default:
                            nameTags = "<div><span id=\"tagZoneCatalogName" + id + "\" class=\"label label-default\" style=\"display: none;\"></span></div>";
                            break;
                    }
                }

                tableHtmlRows += "<tr id=\"trZone" + id + "\"><td>" + (firstRowNumber + i) + "</td>";

                if (zones[i].nameIdn == null)
                    tableHtmlRows += "<td style=\"word-break: break-word; max-width: 390px;\"><a href=\"#\" style=\"font-weight: bold;\" onclick=\"showEditZone('" + name + "'); return false;\">" + htmlEncode(name === "." ? "<root>" : name) + "</a>" + nameTags + "</td>";
                else
                    tableHtmlRows += "<td style=\"word-break: break-word; max-width: 390px;\"><a href=\"#\" style=\"font-weight: bold;\" onclick=\"showEditZone('" + name + "'); return false;\">" + htmlEncode(zones[i].nameIdn + " (" + name + ")") + "</a>" + nameTags + "</td>";

                tableHtmlRows += "<td>" + type + "</td>";
                tableHtmlRows += "<td>" + dnssecStatus + "</td>";
                tableHtmlRows += "<td>" + status + "</td>";
                tableHtmlRows += "<td>" + soaSerial + "</td>";
                tableHtmlRows += "<td>" + expiry + "</td>";
                tableHtmlRows += "<td>" + lastModified + "</td>";

                tableHtmlRows += "<td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnZoneRowOption" + id + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
                tableHtmlRows += "<li><a href=\"#\" onclick=\"showEditZone('" + name + "'); return false;\">" + (isReadOnlyZone ? "View" : "Edit") + " Zone</a></li>";

                if (!zones[i].internal) {
                    tableHtmlRows += "<li id=\"mnuEnableZone" + id + "\"" + (zones[i].disabled ? "" : " style=\"display: none;\"") + "><a href=\"#\" data-id=\"" + id + "\" data-zone=\"" + htmlEncode(name) + "\" onclick=\"enableZoneMenu(this); return false;\">Enable</a></li>";
                    tableHtmlRows += "<li id=\"mnuDisableZone" + id + "\"" + (!zones[i].disabled ? "" : " style=\"display: none;\"") + "><a href=\"#\" data-id=\"" + id + "\" data-zone=\"" + htmlEncode(name) + "\" onclick=\"disableZoneMenu(this); return false;\">Disable</a></li>";
                }

                if (showResyncMenu) {
                    tableHtmlRows += "<li><a href=\"#\" data-id=\"" + id + "\" data-zone=\"" + htmlEncode(name) + "\" data-zone-type=\"" + zones[i].type + "\" onclick=\"resyncZoneMenu(this); return false;\">Resync</a></li>";
                }

                switch (zones[i].type) {
                    case "Primary":
                    case "Forwarder":
                        tableHtmlRows += "<li><a href=\"#\" onclick=\"showImportZoneModal('" + name + "'); return false;\">Import Zone</a></li>";
                        break;
                }

                switch (zones[i].type) {
                    case "Primary":
                    case "Forwarder":
                    case "Secondary":
                    case "SecondaryForwarder":
                    case "SecondaryCatalog":
                    case "Catalog":
                        tableHtmlRows += "<li><a href=\"#\" onclick=\"exportZone('" + name + "'); return false;\">Export Zone</a></li>";
                        break;
                }

                switch (zones[i].type) {
                    case "Primary":
                    case "Secondary":
                    case "SecondaryForwarder":
                    case "Forwarder":
                    case "SecondaryCatalog":
                        tableHtmlRows += "<li><a href=\"#\" onclick=\"showConvertZoneModal('" + name + "', '" + zones[i].type + "'); return false;\">Convert Zone</a></li>";
                        break;
                }

                switch (zones[i].type) {
                    case "Primary":
                    case "Forwarder":
                        tableHtmlRows += "<li><a href=\"#\" onclick=\"showCloneZoneModal('" + name + "'); return false;\">Clone Zone</a></li>";
                        break;
                }

                if (!zones[i].internal) {
                    tableHtmlRows += "<li><a href=\"#\" onclick=\"showZonePermissionsModal('" + name + "'); return false;\">Permissions</a></li>";
                }

                if (!hideOptionsMenu) {
                    tableHtmlRows += "<li><a href=\"#\" onclick=\"$('#btnSaveZoneOptions').attr('data-zones-row-id', " + id + "); showZoneOptionsModal('" + name + "'); return false;\">Zone Options</a></li>";
                }

                if (!zones[i].internal) {
                    tableHtmlRows += "<li role=\"separator\" class=\"divider\"></li>";
                    tableHtmlRows += "<li><a href=\"#\" data-id=\"" + id + "\" data-zone=\"" + htmlEncode(name) + "\" onclick=\"deleteZoneMenu(this); return false;\">Delete Zone</a></li>";
                }

                tableHtmlRows += "</ul></div></td></tr>";
            }

            var paginationHtml = "";

            if (responseJSON.response.pageNumber > 1) {
                paginationHtml += "<li><a href=\"#\" aria-label=\"First\" onClick=\"refreshZones(false, 1); return false;\"><span aria-hidden=\"true\">&laquo;</span></a></li>";
                paginationHtml += "<li><a href=\"#\" aria-label=\"Previous\" onClick=\"refreshZones(false, " + (responseJSON.response.pageNumber - 1) + "); return false;\"><span aria-hidden=\"true\">&lsaquo;</span></a></li>";
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
                    paginationHtml += "<li class=\"active\"><a href=\"#\" onClick=\"refreshZones(false, " + i + "); return false;\">" + i + "</a></li>";
                else
                    paginationHtml += "<li><a href=\"#\" onClick=\"refreshZones(false, " + i + "); return false;\">" + i + "</a></li>";
            }

            if (responseJSON.response.pageNumber < responseJSON.response.totalPages) {
                paginationHtml += "<li><a href=\"#\" aria-label=\"Next\" onClick=\"refreshZones(false, " + (responseJSON.response.pageNumber + 1) + "); return false;\"><span aria-hidden=\"true\">&rsaquo;</span></a></li>";
                paginationHtml += "<li><a href=\"#\" aria-label=\"Last\" onClick=\"refreshZones(false, -1); return false;\"><span aria-hidden=\"true\">&raquo;</span></a></li>";
            }

            var statusHtml;

            if (responseJSON.response.zones.length > 0)
                statusHtml = firstRowNumber + "-" + lastRowNumber + " (" + responseJSON.response.zones.length + ") of " + responseJSON.response.totalZones + " zones (page " + responseJSON.response.pageNumber + " of " + responseJSON.response.totalPages + ")";
            else
                statusHtml = "0 zones";

            $("#txtZonesPageNumber").val(responseJSON.response.pageNumber);
            $("#tableZonesBody").html(tableHtmlRows);

            $("#tableZonesTopStatus").html(statusHtml);
            $("#tableZonesTopPagination").html(paginationHtml);

            $("#tableZonesFooterStatus").html(statusHtml);
            $("#tableZonesFooterPagination").html(paginationHtml);

            divViewZonesLoader.hide();
            divViewZones.show();
        },
        error: function () {
            divViewZonesLoader.hide();
            divViewZones.show();
        },
        invalidToken: function () {
            divViewZonesLoader.hide();
            showPageLogin();
        },
        objLoaderPlaceholder: divViewZonesLoader
    });
}

function enableZoneMenu(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var zone = mnuItem.attr("data-zone");

    var node = $("#optZonesClusterNode").val();

    var btn = $("#btnZoneRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<img src='/img/loader-small.gif'/>");

    HTTPRequest({
        url: "api/zones/enable?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);

            $("#mnuEnableZone" + id).hide();
            $("#mnuDisableZone" + id).show();
            $("#tdZoneStatus" + id).attr("class", "label label-success");
            $("#tdZoneStatus" + id).html("Enabled");

            showAlert("success", "Zone Enabled!", "Zone '" + zone + "' was enabled successfully.");
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function enableZone(objBtn) {
    var zone = $("#titleEditZone").attr("data-zone");

    var node = $("#optZonesClusterNode").val();

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/zones/enable?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            btn.button("reset");

            $("#btnEnableZoneEditZone").hide();
            $("#btnDisableZoneEditZone").show();
            $("#titleEditZoneStatus").attr("class", "label label-success");
            $("#titleEditZoneStatus").html("Enabled");

            showAlert("success", "Zone Enabled!", "Zone '" + zone + "' was enabled successfully.");
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

function disableZoneMenu(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var zone = mnuItem.attr("data-zone");

    if (!confirm("Are you sure you want to disable the zone '" + zone + "'?"))
        return;

    var node = $("#optZonesClusterNode").val();

    var btn = $("#btnZoneRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<img src='/img/loader-small.gif'/>");

    HTTPRequest({
        url: "api/zones/disable?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);

            $("#mnuEnableZone" + id).show();
            $("#mnuDisableZone" + id).hide();
            $("#tdZoneStatus" + id).attr("class", "label label-warning");
            $("#tdZoneStatus" + id).html("Disabled");

            showAlert("success", "Zone Disabled!", "Zone '" + zone + "' was disabled successfully.");
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function disableZone(objBtn) {
    var zone = $("#titleEditZone").attr("data-zone");

    if (!confirm("Are you sure you want to disable the zone '" + zone + "'?"))
        return;

    var node = $("#optZonesClusterNode").val();

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/zones/disable?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            btn.button("reset");

            $("#btnEnableZoneEditZone").show();
            $("#btnDisableZoneEditZone").hide();
            $("#titleEditZoneStatus").attr("class", "label label-warning");
            $("#titleEditZoneStatus").html("Disabled");

            showAlert("success", "Zone Disabled!", "Zone '" + zone + "' was disabled successfully.");
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

function deleteZoneMenu(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var zone = mnuItem.attr("data-zone");

    if (!confirm("Are you sure you want to permanently delete the zone '" + zone + "' and all its records?"))
        return;

    var node = $("#optZonesClusterNode").val();

    var btn = $("#btnZoneRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<img src='/img/loader-small.gif'/>");

    HTTPRequest({
        url: "api/zones/delete?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            refreshZones();

            showAlert("success", "Zone Deleted!", "Zone '" + zone + "' was deleted successfully.");
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function deleteZone(objBtn) {
    var zone = $("#titleEditZone").attr("data-zone");

    if (!confirm("Are you sure you want to permanently delete the zone '" + zone + "' and all its records?"))
        return;

    var node = $("#optZonesClusterNode").val();

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/zones/delete?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            btn.button("reset");
            refreshZones();

            showAlert("success", "Zone Deleted!", "Zone '" + zone + "' was deleted successfully.");
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

function showImportZoneModal(zone) {
    $("#lblImportZoneName").text(zone);
    $("#divImportZoneAlert").html("");

    $("#rdImportZoneTypeFile").prop("checked", true);
    $("#chkImportZoneOverwrite").prop("checked", true)
    $("#chkImportZoneOverwriteSoaSerial").prop("checked", false)

    $("#divImportZoneFile").show();
    $("#fileImportZone").val("");

    $("#divImportZoneTextEditor").hide();
    $("#txtImportZoneText").val("");

    $("#btnImportZone").button("reset");

    $("#modalImportZone").modal("show");

    setTimeout(function () {
        $("#txtImportZoneText").trigger("focus");
    }, 1000);
}

function importZone() {
    var divImportZoneAlert = $("#divImportZoneAlert");

    var zone = $("#lblImportZoneName").text();
    var importType = $("input[name=rdImportZoneType]:checked").val();
    var overwrite = $("#chkImportZoneOverwrite").prop("checked");
    var overwriteSoaSerial = $("#chkImportZoneOverwriteSoaSerial").prop("checked");

    var formData;
    var contentType;

    switch (importType) {
        case "File":
            var fileImportZone = $("#fileImportZone");

            if (fileImportZone[0].files.length === 0) {
                showAlert("warning", "Missing!", "Please select a zone file to import.", divImportZoneAlert);
                fileImportZone.trigger("focus");
                return;
            }

            formData = new FormData();
            formData.append("fileImportZone", fileImportZone[0].files[0]);
            contentType = false;
            break;

        default:
            formData = $("#txtImportZoneText").val();
            contentType = "text/plain";
            break;
    }

    var node = $("#optZonesClusterNode").val();

    var btn = $("#btnImportZone");
    btn.button("loading");

    HTTPRequest({
        url: "api/zones/import?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&overwrite=" + overwrite + "&overwriteSoaSerial=" + overwriteSoaSerial + "&node=" + encodeURIComponent(node),
        method: "POST",
        data: formData,
        contentType: contentType,
        processData: false,
        success: function (responseJSON) {
            $("#modalImportZone").modal("hide");

            if ($("#divEditZone").is(":visible"))
                showEditZone(zone);

            showAlert("success", "Zone Imported!", "The zone file was imported successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            $("#modalImportZone").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divImportZoneAlert
    });
}

function exportZone(zone) {
    var node = $("#optZonesClusterNode").val();

    window.open("api/zones/export?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&node=" + encodeURIComponent(node), "_blank");

    showAlert("success", "Zone Exported!", "Zone file was exported successfully.");
}

function showCloneZoneModal(sourceZone) {
    $("#lblCloneZoneZoneName").text(sourceZone === "." ? "<root>" : sourceZone);

    $("#divCloneZoneAlert").html("");
    $("#txtCloneZoneSourceZoneName").val(sourceZone);
    $("#txtCloneZoneZoneName").val("");

    $("#modalCloneZone").modal("show");

    setTimeout(function () {
        $("#txtCloneZoneZoneName").trigger("focus");
    }, 1000);
}

function cloneZone(objBtn) {
    var divCloneZoneAlert = $("#divCloneZoneAlert");

    var sourceZone = $("#txtCloneZoneSourceZoneName").val();

    var zone = $("#txtCloneZoneZoneName").val();
    if ((zone == null) || (zone === "")) {
        showAlert("warning", "Missing!", "Please enter a domain name for the new zone.", divCloneZoneAlert);
        $("#txtCloneZoneZoneName").trigger("focus");
        return;
    }

    var node = $("#optZonesClusterNode").val();

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/zones/clone?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&sourceZone=" + encodeURIComponent(sourceZone) + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            btn.button("reset");
            $("#modalCloneZone").modal("hide");

            if ($("#divEditZone").is(":hidden"))
                refreshZones();

            showAlert("success", "Zone Cloned!", "Zone was cloned from successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalCloneZone").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divCloneZoneAlert
    });
}

function showConvertZoneModal(zone, type) {
    var lblConvertZoneZoneName = $("#lblConvertZoneZoneName");

    lblConvertZoneZoneName.text(zone === "." ? "<root>" : zone);
    lblConvertZoneZoneName.attr("data-zone", zone);

    $("#divConvertZoneAlert").html("");

    switch (type) {
        case "Primary":
            $("#rdConvertZoneToTypePrimary").attr("disabled", true);
            $("#rdConvertZoneToTypeForwarder").attr("disabled", false);
            $("#rdConvertZoneToTypeCatalog").attr("disabled", true);

            $("#rdConvertZoneToTypeForwarder").prop("checked", true);
            break;

        case "Secondary":
        case "SecondaryForwarder":
            $("#rdConvertZoneToTypePrimary").attr("disabled", false);
            $("#rdConvertZoneToTypeForwarder").attr("disabled", false);
            $("#rdConvertZoneToTypeCatalog").attr("disabled", true);

            $("#rdConvertZoneToTypePrimary").prop("checked", true);
            break;

        case "Forwarder":
            $("#rdConvertZoneToTypePrimary").attr("disabled", false);
            $("#rdConvertZoneToTypeForwarder").attr("disabled", true);
            $("#rdConvertZoneToTypeCatalog").attr("disabled", true);

            $("#rdConvertZoneToTypePrimary").prop("checked", true);
            break;

        case "SecondaryCatalog":
            $("#rdConvertZoneToTypePrimary").attr("disabled", true);
            $("#rdConvertZoneToTypeForwarder").attr("disabled", true);
            $("#rdConvertZoneToTypeCatalog").attr("disabled", false);

            $("#rdConvertZoneToTypeCatalog").prop("checked", true);
            break;

        default:
            $("#rdConvertZoneToTypePrimary").attr("disabled", true);
            $("#rdConvertZoneToTypeForwarder").attr("disabled", true);
            $("#rdConvertZoneToTypeCatalog").attr("disabled", true);

            $("#rdConvertZoneToTypePrimary").prop("checked", false);
            $("#rdConvertZoneToTypeForwarder").prop("checked", false);
            $("#rdConvertZoneToTypeCatalog").prop("checked", false);
            break;
    }

    $("#modalConvertZone").modal("show");
}

function convertZone(objBtn) {
    var divConvertZoneAlert = $("#divConvertZoneAlert");

    var zone = $("#lblConvertZoneZoneName").attr("data-zone");
    var type = $("input[name=rdConvertZoneToType]:checked").val();

    var node = $("#optZonesClusterNode").val();

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/zones/convert?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&type=" + type + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            btn.button("reset");
            $("#modalConvertZone").modal("hide");

            if ($("#divEditZone").is(":visible"))
                showEditZone(zone);
            else
                refreshZones();

            showAlert("success", "Zone Converted!", "The zone was converted successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalConvertZone").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divConvertZoneAlert
    });
}

function addZoneOptionsDynamicUpdatesSecurityPolicyRow(id, tsigKeyName, domain, allowedTypes) {
    var tbodyDynamicUpdateSecurityPolicy = $("#tbodyDynamicUpdateSecurityPolicy");

    if (id == null) {
        id = Math.floor(Math.random() * 10000);

        if (tbodyDynamicUpdateSecurityPolicy.is(":empty")) {
            tsigKeyName = null;
            domain = $("#lblZoneOptionsZoneName").attr("data-zone");
            allowedTypes = 'A,AAAA'.split(',');
        }
    }

    var tableHtmlRow = "<tr id=\"trDynamicUpdateSecurityPolicyRow" + id + "\"><td style=\"word-wrap: anywhere;\"><select class=\"form-control\">";

    if (tsigKeyName != null)
        tableHtmlRow += "<option selected>" + htmlEncode(tsigKeyName) + "</option>";

    for (var i = 0; i < zoneOptionsAvailableTsigKeyNames.length; i++) {
        if (zoneOptionsAvailableTsigKeyNames[i] === tsigKeyName)
            continue;

        tableHtmlRow += "<option>" + htmlEncode(zoneOptionsAvailableTsigKeyNames[i]) + "</option>";
    }

    tableHtmlRow += "</select></td>";
    tableHtmlRow += "<td><input class=\"form-control\" type=\"text\" value=\"" + htmlEncode(domain) + "\"></td>";
    tableHtmlRow += "<td><input class=\"form-control\" type=\"text\" value=\"";

    if (allowedTypes != null) {
        for (var i = 0; i < allowedTypes.length; i++) {
            if (i == 0)
                tableHtmlRow += htmlEncode(allowedTypes[i]);
            else
                tableHtmlRow += ", " + htmlEncode(allowedTypes[i]);
        }
    }

    tableHtmlRow += "\"></td>";
    tableHtmlRow += "<td align=\"right\"><button type=\"button\" class=\"btn btn-warning\" style=\"padding: 5px 7px;\" onclick=\"$('#trDynamicUpdateSecurityPolicyRow" + id + "').remove();\">Remove</button></td></tr>";

    tbodyDynamicUpdateSecurityPolicy.append(tableHtmlRow);
}

function showZoneOptionsModal(zone) {
    var divZoneOptionsAlert = $("#divZoneOptionsAlert");
    var divZoneOptionsLoader = $("#divZoneOptionsLoader");
    var divZoneOptions = $("#divZoneOptions");

    $("#lblZoneOptionsZoneName").text(zone === "." ? "<root>" : zone);
    $("#lblZoneOptionsZoneName").attr("data-zone", zone);
    divZoneOptionsLoader.show();
    divZoneOptions.hide();

    var node = $("#optZonesClusterNode").val();

    $("#modalZoneOptions").modal("show");

    HTTPRequest({
        url: "api/zones/options/get?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&includeAvailableCatalogZoneNames=true&includeAvailableTsigKeyNames=true" + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            $("#optZoneOptionsCatalogZoneName").html("");

            $("#lblZoneOptionsPrimaryNameServerAddresses").text("Primary Name Server Addresses (Optional)");
            $("#divZoneOptionsPrimaryNameServerAddressesInfo").text("Enter the primary name server addresses to sync the zone from. When unspecified, the SOA Primary Name Server will be resolved and used.");
            $("#txtZoneOptionsPrimaryNameServerAddresses").val("");
            $("#rdPrimaryZoneTransferProtocolTcp").prop("checked", true);
            $("#optZoneOptionsPrimaryZoneTransferTsigKeyName").val("");
            $("#chkZoneOptionsValidateZone").prop("checked", false);

            $("#tabListZoneOptionsGeneral").hide();

            $("#divZoneOptionsCatalogNotifyFailedNameServers").hide();

            $("#rdDynamicUpdateDeny").prop("checked", true);
            $("#txtDynamicUpdateNetworkACL").val("");
            $("#tbodyDynamicUpdateSecurityPolicy").html("");

            $("#txtQueryAccessNetworkACL").prop("disabled", true);
            $("#txtZoneTransferNetworkACL").prop("disabled", true);
            $("#txtZoneNotifyNameServers").prop("disabled", true);
            $("#txtZoneNotifySecondaryCatalogNameServers").prop("disabled", true);
            $("#txtDynamicUpdateNetworkACL").prop("disabled", true);

            $("#lblZoneOptionsZoneName").attr("data-zone-type", responseJSON.response.type);

            //catalog zone
            switch (responseJSON.response.type) {
                case "Primary":
                case "Forwarder":
                    if (responseJSON.response.availableCatalogZoneNames.length > 0) {
                        loadCatalogZoneNamesFrom(responseJSON.response.availableCatalogZoneNames, $("#optZoneOptionsCatalogZoneName"), responseJSON.response.catalog);
                        $("#optZoneOptionsCatalogZoneName").prop("disabled", false);

                        $("#chkZoneOptionsCatalogOverrideQueryAccess").prop("checked", (responseJSON.response.catalog != null) && responseJSON.response.overrideCatalogQueryAccess);
                        $("#chkZoneOptionsCatalogOverrideZoneTransfer").prop("checked", (responseJSON.response.catalog != null) && responseJSON.response.overrideCatalogZoneTransfer);
                        $("#chkZoneOptionsCatalogOverrideNotify").prop("checked", (responseJSON.response.catalog != null) && responseJSON.response.overrideCatalogNotify);

                        $("#chkZoneOptionsCatalogOverrideQueryAccess").prop("disabled", (responseJSON.response.catalog == null));
                        $("#chkZoneOptionsCatalogOverrideZoneTransfer").prop("disabled", (responseJSON.response.catalog == null));
                        $("#chkZoneOptionsCatalogOverrideNotify").prop("disabled", (responseJSON.response.catalog == null));

                        $("#divZoneOptionsCatalogOverrideZoneTransfer").show();
                        $("#divZoneOptionsCatalogOverrideNotify").show();

                        $("#divZoneOptionsCatalogOverrideOptions").show();
                        $("#divZoneOptionsGeneralCatalogZone").show();
                        $("#tabListZoneOptionsGeneral").show();
                    } else {
                        $("#divZoneOptionsGeneralCatalogZone").hide();
                    }
                    break;

                case "Stub":
                    if ((responseJSON.response.catalog != null) && responseJSON.response.isSecondaryCatalogMember) {
                        $("#optZoneOptionsCatalogZoneName").html("<option selected>" + htmlEncode(responseJSON.response.catalog) + "</option>");
                        $("#optZoneOptionsCatalogZoneName").prop("disabled", true);

                        $("#chkZoneOptionsCatalogOverrideQueryAccess").prop("checked", responseJSON.response.overrideCatalogQueryAccess);
                        $("#chkZoneOptionsCatalogOverrideQueryAccess").prop("disabled", true);

                        $("#divZoneOptionsCatalogOverrideZoneTransfer").hide();
                        $("#divZoneOptionsCatalogOverrideNotify").hide();

                        $("#divZoneOptionsCatalogOverrideOptions").show();
                        $("#divZoneOptionsGeneralCatalogZone").show();
                        $("#tabListZoneOptionsGeneral").show();
                    } else {
                        if (responseJSON.response.availableCatalogZoneNames.length > 0) {
                            loadCatalogZoneNamesFrom(responseJSON.response.availableCatalogZoneNames, $("#optZoneOptionsCatalogZoneName"), responseJSON.response.catalog);
                            $("#optZoneOptionsCatalogZoneName").prop("disabled", false);

                            $("#chkZoneOptionsCatalogOverrideQueryAccess").prop("checked", (responseJSON.response.catalog != null) && responseJSON.response.overrideCatalogQueryAccess);
                            $("#chkZoneOptionsCatalogOverrideQueryAccess").prop("disabled", (responseJSON.response.catalog == null));

                            $("#divZoneOptionsCatalogOverrideZoneTransfer").hide();
                            $("#divZoneOptionsCatalogOverrideNotify").hide();

                            $("#divZoneOptionsCatalogOverrideOptions").show();
                            $("#divZoneOptionsGeneralCatalogZone").show();
                            $("#tabListZoneOptionsGeneral").show();
                        } else {
                            $("#divZoneOptionsGeneralCatalogZone").hide();
                        }
                    }

                    break;

                case "Secondary":
                    if (responseJSON.response.catalog != null) {
                        $("#optZoneOptionsCatalogZoneName").html("<option selected>" + htmlEncode(responseJSON.response.catalog) + "</option>");
                        $("#optZoneOptionsCatalogZoneName").prop("disabled", true);

                        $("#chkZoneOptionsCatalogOverrideQueryAccess").prop("checked", responseJSON.response.overrideCatalogQueryAccess);
                        $("#chkZoneOptionsCatalogOverrideZoneTransfer").prop("checked", responseJSON.response.overrideCatalogZoneTransfer);

                        $("#chkZoneOptionsCatalogOverrideQueryAccess").prop("disabled", true);
                        $("#chkZoneOptionsCatalogOverrideZoneTransfer").prop("disabled", true);

                        $("#divZoneOptionsCatalogOverrideZoneTransfer").show();
                        $("#divZoneOptionsCatalogOverrideNotify").hide();

                        $("#divZoneOptionsCatalogOverrideOptions").show();
                        $("#divZoneOptionsGeneralCatalogZone").show();
                        $("#tabListZoneOptionsGeneral").show();
                    } else {
                        $("#divZoneOptionsGeneralCatalogZone").hide();
                    }
                    break;

                case "SecondaryForwarder":
                    if (responseJSON.response.catalog != null) {
                        $("#optZoneOptionsCatalogZoneName").html("<option selected>" + htmlEncode(responseJSON.response.catalog) + "</option>");
                        $("#optZoneOptionsCatalogZoneName").prop("disabled", true);

                        $("#chkZoneOptionsCatalogOverrideQueryAccess").prop("checked", responseJSON.response.overrideCatalogQueryAccess);
                        $("#chkZoneOptionsCatalogOverrideQueryAccess").prop("disabled", true);

                        $("#divZoneOptionsCatalogOverrideZoneTransfer").hide();
                        $("#divZoneOptionsCatalogOverrideNotify").hide();

                        $("#divZoneOptionsCatalogOverrideOptions").show();
                        $("#divZoneOptionsGeneralCatalogZone").show();
                        $("#tabListZoneOptionsGeneral").show();
                    } else {
                        $("#divZoneOptionsGeneralCatalogZone").hide();
                    }
                    break;

                default:
                    $("#divZoneOptionsGeneralCatalogZone").hide();
                    break;
            }

            //primary server
            switch (responseJSON.response.type) {
                case "Secondary":
                case "SecondaryForwarder":
                case "SecondaryCatalog":
                    {
                        var value = "";

                        for (var i = 0; i < responseJSON.response.primaryNameServerAddresses.length; i++)
                            value += responseJSON.response.primaryNameServerAddresses[i] + "\r\n";

                        $("#txtZoneOptionsPrimaryNameServerAddresses").val(value);
                    }

                    switch (responseJSON.response.primaryZoneTransferProtocol) {
                        case "Tls":
                            $("#rdPrimaryZoneTransferProtocolTls").prop("checked", true);
                            break;

                        case "Quic":
                            $("#rdPrimaryZoneTransferProtocolQuic").prop("checked", true);
                            break;

                        case "Tcp":
                        default:
                            $("#rdPrimaryZoneTransferProtocolTcp").prop("checked", true);
                            break;
                    }

                    loadTsigKeyNamesFrom(responseJSON.response.availableTsigKeyNames, $("#optZoneOptionsPrimaryZoneTransferTsigKeyName"), responseJSON.response.primaryZoneTransferTsigKeyName);

                    if (responseJSON.response.type == "Secondary") {
                        $("#chkZoneOptionsValidateZone").prop("checked", responseJSON.response.validateZone);
                        $("#divZoneOptionsPrimaryServerValidateZone").show();
                    }
                    else {
                        $("#divZoneOptionsPrimaryServerValidateZone").hide();
                    }

                    switch (responseJSON.response.type) {
                        case "SecondaryForwarder":
                        case "SecondaryCatalog":
                            $("#lblZoneOptionsPrimaryNameServerAddresses").text("Primary Name Server Addresses");
                            $("#divZoneOptionsPrimaryNameServerAddressesInfo").text("Enter the primary name server addresses to sync the zone from.");
                            break;
                    }

                    $("#divZoneOptionsPrimaryServerZoneTransferProtocol").show();
                    $("#divZoneOptionsPrimaryServerZoneTransferTsigKeyName").show();

                    $("#txtZoneOptionsPrimaryNameServerAddresses").prop("disabled", responseJSON.response.catalog != null);
                    $("#rdPrimaryZoneTransferProtocolTcp").prop("disabled", responseJSON.response.catalog != null);
                    $("#rdPrimaryZoneTransferProtocolTls").prop("disabled", responseJSON.response.catalog != null);
                    $("#rdPrimaryZoneTransferProtocolQuic").prop("disabled", responseJSON.response.catalog != null);
                    $("#optZoneOptionsPrimaryZoneTransferTsigKeyName").prop("disabled", responseJSON.response.catalog != null);

                    switch (responseJSON.response.type) {
                        case "Secondary":
                        case "SecondaryForwarder":
                            if (responseJSON.response.catalog == null) {
                                $("#divZoneOptionsGeneralPrimaryServer").show();
                                $("#tabListZoneOptionsGeneral").show();
                            } else if (responseJSON.response.overrideCatalogPrimaryNameServers) {
                                $("#divZoneOptionsPrimaryServerValidateZone").hide();
                                $("#divZoneOptionsGeneralPrimaryServer").show();
                                $("#tabListZoneOptionsGeneral").show();
                            } else {
                                $("#divZoneOptionsGeneralPrimaryServer").hide();
                            }

                            break;

                        default:
                            $("#divZoneOptionsGeneralPrimaryServer").show();
                            $("#tabListZoneOptionsGeneral").show();
                            break;
                    }

                    break;

                case "Stub":
                    {
                        var value = "";

                        for (var i = 0; i < responseJSON.response.primaryNameServerAddresses.length; i++)
                            value += responseJSON.response.primaryNameServerAddresses[i] + "\r\n";

                        $("#txtZoneOptionsPrimaryNameServerAddresses").val(value);
                    }

                    if ((responseJSON.response.catalog != null) && responseJSON.response.isSecondaryCatalogMember)
                        $("#txtZoneOptionsPrimaryNameServerAddresses").prop("disabled", true);
                    else
                        $("#txtZoneOptionsPrimaryNameServerAddresses").prop("disabled", false);

                    $("#divZoneOptionsPrimaryServerZoneTransferProtocol").hide();
                    $("#divZoneOptionsPrimaryServerZoneTransferTsigKeyName").hide();
                    $("#divZoneOptionsPrimaryServerValidateZone").hide();
                    $("#divZoneOptionsGeneralPrimaryServer").show();
                    $("#tabListZoneOptionsGeneral").show();
                    break;

                default:
                    $("#divZoneOptionsGeneralPrimaryServer").hide();
                    break;
            }

            //query access
            {
                switch (responseJSON.response.queryAccess) {
                    case "Allow":
                        $("#rdQueryAccessAllow").prop("checked", true);
                        break;

                    case "AllowOnlyPrivateNetworks":
                        $("#rdQueryAccessAllowOnlyPrivateNetworks").prop("checked", true);
                        break;

                    case "AllowOnlyZoneNameServers":
                        $("#rdQueryAccessAllowOnlyZoneNameServers").prop("checked", true);
                        break;

                    case "UseSpecifiedNetworkACL":
                        $("#rdQueryAccessUseSpecifiedNetworkACL").prop("checked", true);
                        $("#txtQueryAccessNetworkACL").prop("disabled", false);
                        break;

                    case "AllowZoneNameServersAndUseSpecifiedNetworkACL":
                        $("#rdQueryAccessAllowZoneNameServersAndUseSpecifiedNetworkACL").prop("checked", true);
                        $("#txtQueryAccessNetworkACL").prop("disabled", false);
                        break;

                    case "Deny":
                    default:
                        $("#rdQueryAccessDeny").prop("checked", true);
                        break;
                }

                switch (responseJSON.response.type) {
                    case "Stub":
                    case "Forwarder":
                    case "SecondaryForwarder":
                    case "Catalog":
                    case "SecondaryCatalog":
                        $("#divQueryAccessAllowOnlyZoneNameServers").hide();
                        $("#divQueryAccessAllowZoneNameServersAndUseSpecifiedNetworkACL").hide();
                        break;

                    default:
                        $("#divQueryAccessAllowOnlyZoneNameServers").show();
                        $("#divQueryAccessAllowZoneNameServersAndUseSpecifiedNetworkACL").show();
                        break;
                }

                {
                    var value = "";

                    for (var i = 0; i < responseJSON.response.queryAccessNetworkACL.length; i++)
                        value += responseJSON.response.queryAccessNetworkACL[i] + "\r\n";

                    $("#txtQueryAccessNetworkACL").val(value);
                }

                switch (responseJSON.response.type) {
                    case "Primary":
                    case "Forwarder":
                    case "Catalog":
                        if ((responseJSON.response.catalog == null) || responseJSON.response.overrideCatalogQueryAccess) {
                            $("#rdQueryAccessDeny").prop("disabled", false);
                            $("#rdQueryAccessAllow").prop("disabled", false);
                            $("#rdQueryAccessAllowOnlyPrivateNetworks").prop("disabled", false);
                            $("#rdQueryAccessAllowOnlyZoneNameServers").prop("disabled", false);
                            $("#rdQueryAccessUseSpecifiedNetworkACL").prop("disabled", false);
                            $("#rdQueryAccessAllowZoneNameServersAndUseSpecifiedNetworkACL").prop("disabled", false);

                            $("#tabListZoneOptionsQueryAccess").show();
                        }
                        else {
                            $("#tabListZoneOptionsQueryAccess").hide();
                        }

                        break;

                    case "Stub":
                        if ((responseJSON.response.catalog != null) && responseJSON.response.isSecondaryCatalogMember) {
                            if (responseJSON.response.overrideCatalogQueryAccess) {
                                $("#rdQueryAccessDeny").prop("disabled", true);
                                $("#rdQueryAccessAllow").prop("disabled", true);
                                $("#rdQueryAccessAllowOnlyPrivateNetworks").prop("disabled", true);
                                $("#rdQueryAccessAllowOnlyZoneNameServers").prop("disabled", true);
                                $("#rdQueryAccessUseSpecifiedNetworkACL").prop("disabled", true);
                                $("#rdQueryAccessAllowZoneNameServersAndUseSpecifiedNetworkACL").prop("disabled", true);
                                $("#txtQueryAccessNetworkACL").prop("disabled", true);

                                $("#tabListZoneOptionsQueryAccess").show();
                            }
                            else {
                                $("#tabListZoneOptionsQueryAccess").hide();
                            }
                        }
                        else {
                            if ((responseJSON.response.catalog == null) || responseJSON.response.overrideCatalogQueryAccess) {
                                $("#rdQueryAccessDeny").prop("disabled", false);
                                $("#rdQueryAccessAllow").prop("disabled", false);
                                $("#rdQueryAccessAllowOnlyPrivateNetworks").prop("disabled", false);
                                $("#rdQueryAccessAllowOnlyZoneNameServers").prop("disabled", false);
                                $("#rdQueryAccessUseSpecifiedNetworkACL").prop("disabled", false);
                                $("#rdQueryAccessAllowZoneNameServersAndUseSpecifiedNetworkACL").prop("disabled", false);

                                $("#tabListZoneOptionsQueryAccess").show();
                            }
                            else {
                                $("#tabListZoneOptionsQueryAccess").hide();
                            }
                        }

                        break;

                    case "Secondary":
                    case "SecondaryForwarder":
                        if ((responseJSON.response.catalog == null) || responseJSON.response.overrideCatalogQueryAccess) {
                            $("#rdQueryAccessDeny").prop("disabled", responseJSON.response.catalog != null);
                            $("#rdQueryAccessAllow").prop("disabled", responseJSON.response.catalog != null);
                            $("#rdQueryAccessAllowOnlyPrivateNetworks").prop("disabled", responseJSON.response.catalog != null);
                            $("#rdQueryAccessAllowOnlyZoneNameServers").prop("disabled", responseJSON.response.catalog != null);
                            $("#rdQueryAccessUseSpecifiedNetworkACL").prop("disabled", responseJSON.response.catalog != null);
                            $("#rdQueryAccessAllowZoneNameServersAndUseSpecifiedNetworkACL").prop("disabled", responseJSON.response.catalog != null);

                            if (responseJSON.response.catalog != null)
                                $("#txtQueryAccessNetworkACL").prop("disabled", true);

                            $("#tabListZoneOptionsQueryAccess").show();
                        }
                        else {
                            $("#tabListZoneOptionsQueryAccess").hide();
                        }

                        break;

                    case "SecondaryCatalog":
                        $("#rdQueryAccessDeny").prop("disabled", true);
                        $("#rdQueryAccessAllow").prop("disabled", true);
                        $("#rdQueryAccessAllowOnlyPrivateNetworks").prop("disabled", true);
                        $("#rdQueryAccessAllowOnlyZoneNameServers").prop("disabled", true);
                        $("#rdQueryAccessUseSpecifiedNetworkACL").prop("disabled", true);
                        $("#rdQueryAccessAllowZoneNameServersAndUseSpecifiedNetworkACL").prop("disabled", true);
                        $("#txtQueryAccessNetworkACL").prop("disabled", true);

                        $("#tabListZoneOptionsQueryAccess").show();
                        break;

                    default:
                        $("#tabListZoneOptionsQueryAccess").hide();
                        break;
                }
            }

            //zone transfer
            switch (responseJSON.response.type) {
                case "Primary":
                case "Secondary":
                case "Forwarder":
                case "Catalog":
                case "SecondaryCatalog":
                    switch (responseJSON.response.zoneTransfer) {
                        case "Allow":
                            $("#rdZoneTransferAllow").prop("checked", true);
                            break;

                        case "AllowOnlyZoneNameServers":
                            $("#rdZoneTransferAllowOnlyZoneNameServers").prop("checked", true);
                            break;

                        case "UseSpecifiedNetworkACL":
                            $("#rdZoneTransferUseSpecifiedNetworkACL").prop("checked", true);
                            $("#txtZoneTransferNetworkACL").prop("disabled", false);
                            break;

                        case "AllowZoneNameServersAndUseSpecifiedNetworkACL":
                            $("#rdZoneTransferAllowZoneNameServersAndUseSpecifiedNetworkACL").prop("checked", true);
                            $("#txtZoneTransferNetworkACL").prop("disabled", false);
                            break;

                        case "Deny":
                        default:
                            $("#rdZoneTransferDeny").prop("checked", true);
                            break;
                    }

                    {
                        var value = "";

                        for (var i = 0; i < responseJSON.response.zoneTransferNetworkACL.length; i++)
                            value += responseJSON.response.zoneTransferNetworkACL[i] + "\r\n";

                        $("#txtZoneTransferNetworkACL").val(value);
                    }

                    {
                        var value = "";

                        if (responseJSON.response.zoneTransferTsigKeyNames != null) {
                            for (var i = 0; i < responseJSON.response.zoneTransferTsigKeyNames.length; i++) {
                                value += responseJSON.response.zoneTransferTsigKeyNames[i] + "\r\n";
                            }
                        }

                        $("#txtZoneOptionsZoneTransferTsigKeyNames").val(value);
                    }

                    {
                        var options = "<option value=\"blank\" selected></option><option value=\"none\">None</option>";

                        if (responseJSON.response.availableTsigKeyNames != null) {
                            for (var i = 0; i < responseJSON.response.availableTsigKeyNames.length; i++) {
                                options += "<option>" + htmlEncode(responseJSON.response.availableTsigKeyNames[i]) + "</option>";
                            }
                        }

                        $("#optZoneOptionsQuickTsigKeyNames").html(options);
                    }

                    switch (responseJSON.response.type) {
                        case "Forwarder":
                        case "Catalog":
                        case "SecondaryCatalog":
                            $("#divZoneTransferAllowOnlyZoneNameServers").hide();
                            $("#divZoneTransferAllowZoneNameServersAndUseSpecifiedNetworkACL").hide();
                            break;

                        default:
                            $("#divZoneTransferAllowOnlyZoneNameServers").show();
                            $("#divZoneTransferAllowZoneNameServersAndUseSpecifiedNetworkACL").show();
                            break;
                    }

                    switch (responseJSON.response.type) {
                        case "Primary":
                        case "Forwarder":
                            if ((responseJSON.response.catalog == null) || responseJSON.response.overrideCatalogZoneTransfer) {
                                $("#rdZoneTransferDeny").prop("disabled", false);
                                $("#rdZoneTransferAllow").prop("disabled", false);
                                $("#rdZoneTransferAllowOnlyZoneNameServers").prop("disabled", false);
                                $("#rdZoneTransferUseSpecifiedNetworkACL").prop("disabled", false);
                                $("#rdZoneTransferAllowZoneNameServersAndUseSpecifiedNetworkACL").prop("disabled", false);
                                $("#txtZoneOptionsZoneTransferTsigKeyNames").prop("disabled", false);
                                $("#optZoneOptionsQuickTsigKeyNames").prop("disabled", false);

                                $("#tabListZoneOptionsZoneTranfer").show();
                            }
                            else {
                                $("#tabListZoneOptionsZoneTranfer").hide();
                            }

                            break;

                        case "Secondary":
                            if ((responseJSON.response.catalog == null) || responseJSON.response.overrideCatalogZoneTransfer) {
                                $("#rdZoneTransferDeny").prop("disabled", responseJSON.response.catalog != null);
                                $("#rdZoneTransferAllow").prop("disabled", responseJSON.response.catalog != null);
                                $("#rdZoneTransferAllowOnlyZoneNameServers").prop("disabled", responseJSON.response.catalog != null);
                                $("#rdZoneTransferUseSpecifiedNetworkACL").prop("disabled", responseJSON.response.catalog != null);
                                $("#rdZoneTransferAllowZoneNameServersAndUseSpecifiedNetworkACL").prop("disabled", responseJSON.response.catalog != null);

                                if (responseJSON.response.catalog != null)
                                    $("#txtZoneTransferNetworkACL").prop("disabled", true);

                                $("#txtZoneOptionsZoneTransferTsigKeyNames").prop("disabled", responseJSON.response.catalog != null);
                                $("#optZoneOptionsQuickTsigKeyNames").prop("disabled", responseJSON.response.catalog != null);

                                $("#tabListZoneOptionsZoneTranfer").show();
                            }
                            else {
                                $("#tabListZoneOptionsZoneTranfer").hide();
                            }

                            break;

                        case "Catalog":
                            $("#rdZoneTransferDeny").prop("disabled", false);
                            $("#rdZoneTransferAllow").prop("disabled", false);
                            $("#rdZoneTransferAllowOnlyZoneNameServers").prop("disabled", false);
                            $("#rdZoneTransferUseSpecifiedNetworkACL").prop("disabled", false);
                            $("#rdZoneTransferAllowZoneNameServersAndUseSpecifiedNetworkACL").prop("disabled", false);
                            $("#txtZoneOptionsZoneTransferTsigKeyNames").prop("disabled", false);
                            $("#optZoneOptionsQuickTsigKeyNames").prop("disabled", false);

                            $("#tabListZoneOptionsZoneTranfer").show();
                            break;

                        case "SecondaryCatalog":
                            $("#rdZoneTransferDeny").prop("disabled", true);
                            $("#rdZoneTransferAllow").prop("disabled", true);
                            $("#rdZoneTransferAllowOnlyZoneNameServers").prop("disabled", true);
                            $("#rdZoneTransferUseSpecifiedNetworkACL").prop("disabled", true);
                            $("#rdZoneTransferAllowZoneNameServersAndUseSpecifiedNetworkACL").prop("disabled", true);
                            $("#txtZoneTransferNetworkACL").prop("disabled", true);
                            $("#txtZoneOptionsZoneTransferTsigKeyNames").prop("disabled", true);
                            $("#optZoneOptionsQuickTsigKeyNames").prop("disabled", true);

                            $("#tabListZoneOptionsZoneTranfer").show();
                            break;
                    }

                    break;

                default:
                    $("#tabListZoneOptionsZoneTranfer").hide();
                    break;
            }

            //notify
            switch (responseJSON.response.type) {
                case "Primary":
                case "Secondary":
                case "Forwarder":
                case "Catalog":
                    switch (responseJSON.response.notify) {
                        case "ZoneNameServers":
                            $("#rdZoneNotifyZoneNameServers").prop("checked", true);
                            break;

                        case "SpecifiedNameServers":
                            $("#rdZoneNotifySpecifiedNameServers").prop("checked", true);
                            $("#txtZoneNotifyNameServers").prop("disabled", false);
                            break;

                        case "BothZoneAndSpecifiedNameServers":
                            $("#rdZoneNotifyBothZoneAndSpecifiedNameServers").prop("checked", true);
                            $("#txtZoneNotifyNameServers").prop("disabled", false);
                            break;

                        case "SeparateNameServersForCatalogAndMemberZones":
                            $("#rdZoneNotifySeparateNameServersForCatalogAndMemberZones").prop("checked", true);
                            $("#txtZoneNotifyNameServers").prop("disabled", false);
                            $("#txtZoneNotifySecondaryCatalogNameServers").prop("disabled", false);
                            break;

                        case "None":
                        default:
                            $("#rdZoneNotifyNone").prop("checked", true);
                            break;
                    }

                    {
                        var value = "";

                        for (var i = 0; i < responseJSON.response.notifyNameServers.length; i++)
                            value += responseJSON.response.notifyNameServers[i] + "\r\n";

                        $("#txtZoneNotifyNameServers").val(value);
                    }

                    if (responseJSON.response.notifySecondaryCatalogsNameServers != null) {
                        var value = "";

                        for (var i = 0; i < responseJSON.response.notifySecondaryCatalogsNameServers.length; i++)
                            value += responseJSON.response.notifySecondaryCatalogsNameServers[i] + "\r\n";

                        $("#txtZoneNotifySecondaryCatalogNameServers").val(value);
                    }
                    else {
                        $("#txtZoneNotifySecondaryCatalogNameServers").val("");
                    }

                    if (responseJSON.response.notifyFailed) {
                        var value = "";

                        for (var i = 0; i < responseJSON.response.notifyFailedFor.length; i++) {
                            if (i == 0)
                                value = responseJSON.response.notifyFailedFor[i];
                            else
                                value += ", " + responseJSON.response.notifyFailedFor[i];
                        }

                        if ((responseJSON.response.catalog != null) && !responseJSON.response.overrideCatalogNotify) {
                            $("#divZoneOptionsCatalogNotifyFailedNameServers").show();
                            $("#lblZoneOptionsCatalogNotifyFailedNameServers").text(value);
                        }

                        $("#divZoneNotifyFailedNameServers").show();
                        $("#lblZoneNotifyFailedNameServers").text(value);
                    }
                    else {
                        $("#divZoneNotifyFailedNameServers").hide();
                    }

                    switch (responseJSON.response.type) {
                        case "Forwarder":
                            $("#divZoneNotifyZoneNameServers").hide();
                            $("#divZoneNotifyBothZoneAndSpecifiedNameServers").hide();
                            $("#divZoneNotifySeparateNameServersForCatalogAndMemberZones").hide();
                            $("#divZoneNotifySecondaryCatalogNameServers").hide();
                            break;

                        case "Catalog":
                            $("#divZoneNotifyZoneNameServers").hide();
                            $("#divZoneNotifyBothZoneAndSpecifiedNameServers").hide();
                            $("#divZoneNotifySeparateNameServersForCatalogAndMemberZones").show();
                            $("#divZoneNotifySecondaryCatalogNameServers").show();
                            break;

                        default:
                            $("#divZoneNotifyZoneNameServers").show();
                            $("#divZoneNotifyBothZoneAndSpecifiedNameServers").show();
                            $("#divZoneNotifySeparateNameServersForCatalogAndMemberZones").hide();
                            $("#divZoneNotifySecondaryCatalogNameServers").hide();
                            break;
                    }

                    switch (responseJSON.response.type) {
                        case "Primary":
                        case "Forwarder":
                            if ((responseJSON.response.catalog == null) || responseJSON.response.overrideCatalogNotify)
                                $("#tabListZoneOptionsNotify").show();
                            else
                                $("#tabListZoneOptionsNotify").hide();

                            break;

                        case "Secondary":
                        case "Catalog":
                            $("#tabListZoneOptionsNotify").show();
                            break;
                    }
                    break;

                default:
                    $("#tabListZoneOptionsNotify").hide();
                    break;
            }

            //dynamic update
            switch (responseJSON.response.type) {
                case "Primary":
                case "Secondary":
                case "SecondaryForwarder":
                case "Forwarder":
                    //dynamic update
                    switch (responseJSON.response.update) {
                        case "Allow":
                            $("#rdDynamicUpdateAllow").prop("checked", true);
                            break;

                        case "AllowOnlyZoneNameServers":
                            $("#rdDynamicUpdateAllowOnlyZoneNameServers").prop("checked", true);
                            break;

                        case "UseSpecifiedNetworkACL":
                            $("#rdDynamicUpdateUseSpecifiedNetworkACL").prop("checked", true);
                            $("#txtDynamicUpdateNetworkACL").prop("disabled", false);
                            break;

                        case "AllowZoneNameServersAndUseSpecifiedNetworkACL":
                            $("#rdDynamicUpdateAllowZoneNameServersAndUseSpecifiedNetworkACL").prop("checked", true);
                            $("#txtDynamicUpdateNetworkACL").prop("disabled", false);
                            break;

                        case "Deny":
                        default:
                            $("#rdDynamicUpdateDeny").prop("checked", true);
                            break;
                    }

                    {
                        var value = "";

                        for (var i = 0; i < responseJSON.response.updateNetworkACL.length; i++)
                            value += responseJSON.response.updateNetworkACL[i] + "\r\n";

                        $("#txtDynamicUpdateNetworkACL").val(value);
                    }

                    $("#tbodyDynamicUpdateSecurityPolicy").html("");

                    switch (responseJSON.response.type) {
                        case "Primary":
                        case "Forwarder":
                            zoneOptionsAvailableTsigKeyNames = responseJSON.response.availableTsigKeyNames;

                            if (responseJSON.response.updateSecurityPolicies != null) {
                                for (var i = 0; i < responseJSON.response.updateSecurityPolicies.length; i++)
                                    addZoneOptionsDynamicUpdatesSecurityPolicyRow(i, responseJSON.response.updateSecurityPolicies[i].tsigKeyName, responseJSON.response.updateSecurityPolicies[i].domain, responseJSON.response.updateSecurityPolicies[i].allowedTypes);
                            }

                            $("#divDynamicUpdateSecurityPolicy").show();
                            break;

                        default:
                            $("#divDynamicUpdateSecurityPolicy").hide();
                            break;
                    }

                    switch (responseJSON.response.type) {
                        case "Secondary":
                        case "SecondaryForwarder":
                        case "Forwarder":
                            $("#divDynamicUpdateAllowOnlyZoneNameServers").hide();
                            $("#divDynamicUpdateAllowZoneNameServersAndUseSpecifiedNetworkACL").hide();
                            break;

                        default:
                            $("#divDynamicUpdateAllowOnlyZoneNameServers").show();
                            $("#divDynamicUpdateAllowZoneNameServersAndUseSpecifiedNetworkACL").show();
                            break;
                    }

                    $("#tabListZoneOptionsUpdate").show();
                    break;

                default:
                    $("#tabListZoneOptionsUpdate").hide();
                    break;
            }

            //tab focus
            switch (responseJSON.response.type) {
                case "Secondary":
                case "SecondaryForwarder":
                case "SecondaryCatalog":
                case "Stub":
                    $("#tabListZoneOptionsGeneral").addClass("active");
                    $("#tabPaneZoneOptionsGeneral").addClass("active");
                    $("#tabListZoneOptionsQueryAccess").removeClass("active");
                    $("#tabPaneZoneOptionsQueryAccess").removeClass("active");
                    $("#tabListZoneOptionsZoneTranfer").removeClass("active");
                    $("#tabPaneZoneOptionsZoneTransfer").removeClass("active");
                    $("#tabListZoneOptionsNotify").removeClass("active");
                    $("#tabPaneZoneOptionsNotify").removeClass("active");
                    $("#tabListZoneOptionsUpdate").removeClass("active");
                    $("#tabPaneZoneOptionsUpdate").removeClass("active");
                    break;

                case "Catalog":
                    $("#tabListZoneOptionsGeneral").removeClass("active");
                    $("#tabPaneZoneOptionsGeneral").removeClass("active");
                    $("#tabListZoneOptionsQueryAccess").addClass("active");
                    $("#tabPaneZoneOptionsQueryAccess").addClass("active");
                    $("#tabListZoneOptionsZoneTranfer").removeClass("active");
                    $("#tabPaneZoneOptionsZoneTransfer").removeClass("active");
                    $("#tabListZoneOptionsNotify").removeClass("active");
                    $("#tabPaneZoneOptionsNotify").removeClass("active");
                    $("#tabListZoneOptionsUpdate").removeClass("active");
                    $("#tabPaneZoneOptionsUpdate").removeClass("active");
                    break;

                case "Primary":
                case "Forwarder":
                    if (responseJSON.response.availableCatalogZoneNames.length > 0) {
                        $("#tabListZoneOptionsGeneral").addClass("active");
                        $("#tabPaneZoneOptionsGeneral").addClass("active");
                        $("#tabListZoneOptionsQueryAccess").removeClass("active");
                        $("#tabPaneZoneOptionsQueryAccess").removeClass("active");
                        $("#tabListZoneOptionsZoneTranfer").removeClass("active");
                        $("#tabPaneZoneOptionsZoneTransfer").removeClass("active");
                        $("#tabListZoneOptionsNotify").removeClass("active");
                        $("#tabPaneZoneOptionsNotify").removeClass("active");
                        $("#tabListZoneOptionsUpdate").removeClass("active");
                        $("#tabPaneZoneOptionsUpdate").removeClass("active");
                    }
                    else {
                        $("#tabListZoneOptionsGeneral").removeClass("active");
                        $("#tabPaneZoneOptionsGeneral").removeClass("active");
                        $("#tabListZoneOptionsQueryAccess").addClass("active");
                        $("#tabPaneZoneOptionsQueryAccess").addClass("active");
                        $("#tabListZoneOptionsZoneTranfer").removeClass("active");
                        $("#tabPaneZoneOptionsZoneTransfer").removeClass("active");
                        $("#tabListZoneOptionsNotify").removeClass("active");
                        $("#tabPaneZoneOptionsNotify").removeClass("active");
                        $("#tabListZoneOptionsUpdate").removeClass("active");
                        $("#tabPaneZoneOptionsUpdate").removeClass("active");
                    }
                    break;
            }

            divZoneOptionsLoader.hide();
            divZoneOptions.show();
        },
        error: function () {
            divZoneOptionsLoader.hide();
        },
        invalidToken: function () {
            $("#modalZoneOptions").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divZoneOptionsAlert,
        objLoaderPlaceholder: divZoneOptionsLoader
    });
}

function saveZoneOptions() {
    var divZoneOptionsAlert = $("#divZoneOptionsAlert");
    var divZoneOptionsLoader = $("#divZoneOptionsLoader");
    var zone = $("#lblZoneOptionsZoneName").attr("data-zone");
    var zoneType = $("#lblZoneOptionsZoneName").attr("data-zone-type");

    //general catalog zone name
    var catalog = $("#optZoneOptionsCatalogZoneName").val();
    if (catalog == null)
        catalog = "";

    var overrideCatalogQueryAccess = $("#chkZoneOptionsCatalogOverrideQueryAccess").prop("checked");
    var overrideCatalogZoneTransfer = $("#chkZoneOptionsCatalogOverrideZoneTransfer").prop("checked");
    var overrideCatalogNotify = $("#chkZoneOptionsCatalogOverrideNotify").prop("checked");

    //general primary name server for secondary & stub
    var primaryNameServerAddresses = cleanTextList($("#txtZoneOptionsPrimaryNameServerAddresses").val());

    switch (zoneType) {
        case "SecondaryForwarder":
        case "SecondaryCatalog":
            if ((primaryNameServerAddresses.length === 0) || (primaryNameServerAddresses === ",")) {
                showAlert("warning", "Missing!", "Please enter at least one primary name server address to proceed.", divZoneOptionsAlert);
                $("#txtZoneOptionsPrimaryNameServerAddresses").trigger("focus");
                return;
            }

            break;
    }

    var primaryZoneTransferProtocol = $("input[name=rdPrimaryZoneTransferProtocol]:checked").val();
    var primaryZoneTransferTsigKeyName = $("#optZoneOptionsPrimaryZoneTransferTsigKeyName").val();
    var validateZone = $("#chkZoneOptionsValidateZone").prop("checked");

    //query access
    var queryAccess = $("input[name=rdQueryAccess]:checked").val();

    var queryAccessNetworkACL = cleanTextList($("#txtQueryAccessNetworkACL").val());

    //zone transfer
    var zoneTransfer = $("input[name=rdZoneTransfer]:checked").val();

    var zoneTransferNetworkACL = cleanTextList($("#txtZoneTransferNetworkACL").val());

    if ((zoneTransferNetworkACL.length === 0) || (zoneTransferNetworkACL === ","))
        zoneTransferNetworkACL = false;
    else
        $("#txtZoneTransferNetworkACL").val(zoneTransferNetworkACL.replace(/,/g, "\n"));

    var zoneTransferTsigKeyNames = cleanTextList($("#txtZoneOptionsZoneTransferTsigKeyNames").val());

    if ((zoneTransferTsigKeyNames.length === 0) || (zoneTransferTsigKeyNames === ","))
        zoneTransferTsigKeyNames = false;
    else
        $("#txtZoneOptionsZoneTransferTsigKeyNames").val(zoneTransferTsigKeyNames.replace(/,/g, "\n"));

    //notify
    var notify = $("input[name=rdZoneNotify]:checked").val();

    var notifyNameServers = cleanTextList($("#txtZoneNotifyNameServers").val());

    if ((notifyNameServers.length === 0) || (notifyNameServers === ","))
        notifyNameServers = false;
    else
        $("#txtZoneNotifyNameServers").val(notifyNameServers.replace(/,/g, "\n"));

    var notifySecondaryCatalogsNameServers = cleanTextList($("#txtZoneNotifySecondaryCatalogNameServers").val());

    if ((notifySecondaryCatalogsNameServers.length === 0) || (notifySecondaryCatalogsNameServers === ","))
        notifySecondaryCatalogsNameServers = false;
    else
        $("#txtZoneNotifySecondaryCatalogNameServers").val(notifySecondaryCatalogsNameServers.replace(/,/g, "\n"));

    //dynamic update
    var update = $("input[name=rdDynamicUpdate]:checked").val();

    var updateNetworkACL = cleanTextList($("#txtDynamicUpdateNetworkACL").val());

    if ((updateNetworkACL.length === 0) || (updateNetworkACL === ","))
        updateNetworkACL = false;
    else
        $("#txtDynamicUpdateNetworkACL").val(updateNetworkACL.replace(/,/g, "\n"));

    var updateSecurityPolicies = serializeTableData($("#tableDynamicUpdateSecurityPolicy"), 3, divZoneOptionsAlert);
    if (updateSecurityPolicies === false)
        return;

    if (updateSecurityPolicies.length === 0)
        updateSecurityPolicies = false;

    var node = $("#optZonesClusterNode").val();

    var btn = $("#btnSaveZoneOptions");
    btn.button("loading");

    HTTPRequest({
        url: "api/zones/options/set?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone)
            + "&catalog=" + encodeURIComponent(catalog) + "&overrideCatalogQueryAccess=" + overrideCatalogQueryAccess + "&overrideCatalogZoneTransfer=" + overrideCatalogZoneTransfer + "&overrideCatalogNotify=" + overrideCatalogNotify
            + "&primaryNameServerAddresses=" + encodeURIComponent(primaryNameServerAddresses) + "&primaryZoneTransferProtocol=" + primaryZoneTransferProtocol + "&primaryZoneTransferTsigKeyName=" + encodeURIComponent(primaryZoneTransferTsigKeyName) + "&validateZone=" + validateZone
            + "&queryAccess=" + queryAccess + "&queryAccessNetworkACL=" + encodeURIComponent(queryAccessNetworkACL)
            + "&zoneTransfer=" + zoneTransfer + "&zoneTransferNetworkACL=" + encodeURIComponent(zoneTransferNetworkACL) + "&zoneTransferTsigKeyNames=" + encodeURIComponent(zoneTransferTsigKeyNames)
            + "&notify=" + notify + "&notifyNameServers=" + encodeURIComponent(notifyNameServers) + "&notifySecondaryCatalogsNameServers=" + encodeURIComponent(notifySecondaryCatalogsNameServers)
            + "&update=" + update + "&updateNetworkACL=" + encodeURIComponent(updateNetworkACL) + "&updateSecurityPolicies=" + encodeURIComponent(updateSecurityPolicies)
            + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            btn.button("reset");
            $("#modalZoneOptions").modal("hide");

            var zonesRowId = $("#btnSaveZoneOptions").attr("data-zones-row-id");
            if (zonesRowId == null) {
                switch (zoneType) {
                    case "Catalog":
                    case "SecondaryCatalog":
                        break;

                    default:
                        if ((catalog == null) || (catalog == "")) {
                            $("#titleEditZoneCatalog").hide();
                            $("#titleEditZoneCatalog").text("");
                        }
                        else {
                            $("#titleEditZoneCatalog").attr("class", "label label-default");
                            $("#titleEditZoneCatalog").text(catalog);
                            $("#titleEditZoneCatalog").show();
                        }

                        break;
                }
            }
            else {
                switch (zoneType) {
                    case "Catalog":
                    case "SecondaryCatalog":
                        break;

                    default:
                        if ((catalog == null) || (catalog == "")) {
                            $("#tagZoneCatalogName" + zonesRowId).hide();
                        }
                        else {
                            $("#tagZoneCatalogName" + zonesRowId).text(catalog);
                            $("#tagZoneCatalogName" + zonesRowId).show();
                        }
                        break;
                }
            }

            showAlert("success", "Options Saved!", "Zone options were saved successfully.");
        },
        error: function () {
            btn.button("reset");
            divZoneOptionsLoader.hide();
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalZoneOptions").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divZoneOptionsAlert,
        objLoaderPlaceholder: divZoneOptionsLoader
    });
}

function showZonePermissionsModal(zone) {
    var divEditPermissionsAlert = $("#divEditPermissionsAlert");
    var divEditPermissionsLoader = $("#divEditPermissionsLoader");
    var divEditPermissionsViewer = $("#divEditPermissionsViewer");

    $("#lblEditPermissionsName").text("Zones / " + (zone === "." ? "<root>" : zone));
    $("#tbodyEditPermissionsUser").html("");
    $("#tbodyEditPermissionsGroup").html("");

    divEditPermissionsLoader.show();
    divEditPermissionsViewer.hide();

    var btnEditPermissionsSave = $("#btnEditPermissionsSave");
    btnEditPermissionsSave.attr("onclick", "saveZonePermissions(this); return false;");
    btnEditPermissionsSave.show();

    var node = $("#optZonesClusterNode").val();

    var modalEditPermissions = $("#modalEditPermissions");
    modalEditPermissions.modal("show");

    HTTPRequest({
        url: "api/zones/permissions/get?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&includeUsersAndGroups=true" + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            $("#lblEditPermissionsName").text(responseJSON.response.section + " / " + (responseJSON.response.subItem == "." ? "<root>" : responseJSON.response.subItem));

            //user permissions
            for (var i = 0; i < responseJSON.response.userPermissions.length; i++) {
                addEditPermissionUserRow(i, responseJSON.response.userPermissions[i].username, responseJSON.response.userPermissions[i].canView, responseJSON.response.userPermissions[i].canModify, responseJSON.response.userPermissions[i].canDelete);
            }

            //load users list
            var userListHtml = "<option value=\"blank\" selected></option><option value=\"none\">None</option>";

            for (var i = 0; i < responseJSON.response.users.length; i++) {
                userListHtml += "<option>" + htmlEncode(responseJSON.response.users[i]) + "</option>";
            }

            $("#optEditPermissionsUserList").html(userListHtml);

            //group permissions
            for (var i = 0; i < responseJSON.response.groupPermissions.length; i++) {
                addEditPermissionGroupRow(i, responseJSON.response.groupPermissions[i].name, responseJSON.response.groupPermissions[i].canView, responseJSON.response.groupPermissions[i].canModify, responseJSON.response.groupPermissions[i].canDelete);
            }

            //load groups list
            var groupListHtml = "<option value=\"blank\" selected></option><option value=\"none\">None</option>";

            for (var i = 0; i < responseJSON.response.groups.length; i++) {
                groupListHtml += "<option>" + htmlEncode(responseJSON.response.groups[i]) + "</option>";
            }

            $("#optEditPermissionsGroupList").html(groupListHtml);

            btnEditPermissionsSave.attr("data-zone", responseJSON.response.subItem);

            divEditPermissionsLoader.hide();
            divEditPermissionsViewer.show();
        },
        error: function () {
            divEditPermissionsLoader.hide();
        },
        invalidToken: function () {
            modalEditPermissions.modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divEditPermissionsAlert,
        objLoaderPlaceholder: divEditPermissionsLoader
    });
}

function saveZonePermissions(objBtn) {
    var btn = $(objBtn);
    var divEditPermissionsAlert = $("#divEditPermissionsAlert");

    var zone = btn.attr("data-zone");

    var userPermissions = serializeTableData($("#tableEditPermissionsUser"), 4);
    var groupPermissions = serializeTableData($("#tableEditPermissionsGroup"), 4);

    var node = $("#optZonesClusterNode").val();

    var apiUrl = "api/zones/permissions/set?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&userPermissions=" + encodeURIComponent(userPermissions) + "&groupPermissions=" + encodeURIComponent(groupPermissions);

    btn.button("loading");

    HTTPRequest({
        url: apiUrl + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            btn.button("reset");
            $("#modalEditPermissions").modal("hide");

            showAlert("success", "Permissions Saved!", "Zone permissions were saved successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalEditPermissions").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divEditPermissionsAlert
    });
}

function resyncZoneMenu(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var zone = mnuItem.attr("data-zone");
    var zoneType = mnuItem.attr("data-zone-type");

    if (zoneType == "Secondary") {
        if (!confirm("The resync action will perform a full zone transfer (AXFR). You will need to check the logs to confirm if the resync action was successful.\r\n\r\nAre you sure you want to resync the '" + zone + "' zone?"))
            return;
    }
    else {
        if (!confirm("The resync action will perform a full zone refresh. You will need to check the logs to confirm if the resync action was successful.\r\n\r\nAre you sure you want to resync the '" + zone + "' zone?"))
            return;
    }

    var node = $("#optZonesClusterNode").val();

    var btn = $("#btnZoneRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<img src='/img/loader-small.gif'/>");

    HTTPRequest({
        url: "api/zones/resync?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);

            showAlert("success", "Resync Triggered!", "Zone '" + zone + "' resync was triggered successfully. Please check the Logs for confirmation.");
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function resyncZone(objBtn, zone) {
    if ($("#titleEditZoneType").text() == "Secondary") {
        if (!confirm("The resync action will perform a full zone transfer (AXFR). You will need to check the logs to confirm if the resync action was successful.\r\n\r\nAre you sure you want to resync the '" + zone + "' zone?"))
            return;
    }
    else {
        if (!confirm("The resync action will perform a full zone refresh. You will need to check the logs to confirm if the resync action was successful.\r\n\r\nAre you sure you want to resync the '" + zone + "' zone?"))
            return;
    }

    var node = $("#optZonesClusterNode").val();

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/zones/resync?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            btn.button("reset");
            showAlert("success", "Resync Triggered!", "Zone '" + zone + "' resync was triggered successfully. Please check the Logs for confirmation.");
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

function showAddZoneModal() {
    $("#divAddZoneAlert").html("");

    $("#txtAddZone").val("");
    $("#txtAddZone").prop("disabled", false);
    $("#rdAddZoneTypePrimary").prop("checked", true);
    $("#chkAddZoneInitializeForwarder").prop("checked", true);
    $("#fileAddZoneImportZone").val("");
    $("#chkAddZoneUseSoaSerialDateScheme").prop("checked", $("#chkUseSoaSerialDateScheme").prop("checked"));
    $("#txtAddZonePrimaryNameServerAddresses").val("");
    $("#rdAddZoneZoneTransferProtocolTcp").prop("checked", true);
    $("#optAddZoneTsigKeyName").val("");
    $("#chkAddZoneValidateZone").prop("checked", false);
    $("input[name=rdAddZoneForwarderProtocol]:radio").attr("disabled", false);
    $("#rdAddZoneForwarderProtocolUdp").prop("checked", true);
    $("#chkAddZoneForwarderThisServer").prop("checked", false);
    $("#txtAddZoneForwarder").prop("disabled", false);
    $("#txtAddZoneForwarder").attr("placeholder", "8.8.8.8 or [2620:fe::10]")
    $("#txtAddZoneForwarder").val("");
    $("#chkAddZoneForwarderDnssecValidation").prop("checked", $("#chkDnssecValidation").prop("checked"));
    $("#rdAddZoneForwarderProxyTypeDefaultProxy").prop("checked", true);
    $("#txtAddZoneForwarderProxyAddress").prop("disabled", true);
    $("#txtAddZoneForwarderProxyPort").prop("disabled", true);
    $("#txtAddZoneForwarderProxyUsername").prop("disabled", true);
    $("#txtAddZoneForwarderProxyPassword").prop("disabled", true);
    $("#txtAddZoneForwarderProxyAddress").val("");
    $("#txtAddZoneForwarderProxyPort").val("");
    $("#txtAddZoneForwarderProxyUsername").val("");
    $("#txtAddZoneForwarderProxyPassword").val("");

    $("#divAddZoneCatalogZone").hide();
    $("#divAddZoneInitializeForwarder").hide();
    $("#divAddZoneImportZoneFile").show();
    $("#divAddZoneUseSoaSerialDateScheme").show();
    $("#divAddZonePrimaryNameServerAddresses").hide();
    $("#divAddZoneZoneTransferProtocol").hide();
    $("#divAddZoneTsigKeyName").hide();
    $("#divAddZoneValidateZone").hide();
    $("#divAddZoneForwarderProtocol").hide();
    $("#divAddZoneForwarder").hide();
    $("#divAddZoneForwarderDnssecValidation").hide();
    $("#divAddZoneForwarderProxy").hide();

    $("#btnAddZone").button('reset');

    $("#modalAddZone").modal("show");

    setTimeout(function () {
        $("#txtAddZone").trigger("focus");
    }, 1000);

    var currentValue = null;

    if (sessionData.info.clusterInitialized)
        currentValue = "cluster-catalog." + sessionData.info.clusterDomain;

    loadCatalogZoneNames($("#optAddZoneCatalogZoneName"), currentValue, $("#divAddZoneAlert"), $("#divAddZoneCatalogZone"));
}

function loadCatalogZoneNames(jqDropDown, currentValue, divAlertPlaceholder, divCatalogZone) {
    jqDropDown.prop("disabled", true);
    jqDropDown.attr("hasItems", false);

    if (currentValue == null)
        currentValue = "";

    if (currentValue.length == 0) {
        jqDropDown.html("<option selected></option>");
    }
    else {
        jqDropDown.html("<option></option><option selected>" + htmlEncode(currentValue) + "</option>");
        jqDropDown.val(currentValue);
    }

    var node = $("#optZonesClusterNode").val();

    HTTPRequest({
        url: "api/zones/catalogs/list?token=" + sessionData.token + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            loadCatalogZoneNamesFrom(responseJSON.response.catalogZoneNames, jqDropDown, currentValue);

            if ((divCatalogZone != null) && (responseJSON.response.catalogZoneNames.length > 0))
                divCatalogZone.show();
        },
        error: function () {
            jqDropDown.prop("disabled", false);
        },
        invalidToken: function () {
            jqDropDown.prop("disabled", false);
            showPageLogin();
        },
        objAlertPlaceholder: divAlertPlaceholder
    });
}

function loadCatalogZoneNamesFrom(catalogZoneNames, jqDropDown, currentValue) {
    var optionsHtml;

    if ((currentValue == null) || (currentValue.length == 0))
        optionsHtml = "<option selected></option>";
    else
        optionsHtml = "<option></option>";

    for (var i = 0; i < catalogZoneNames.length; i++) {
        optionsHtml += "<option" + (catalogZoneNames[i] === currentValue ? " selected" : "") + ">" + htmlEncode(catalogZoneNames[i]) + "</option>";
    }

    jqDropDown.html(optionsHtml);
    jqDropDown.prop("disabled", false);
    jqDropDown.attr("hasItems", catalogZoneNames.length > 0);
}

function loadTsigKeyNames(jqDropDown, currentValue, divAlertPlaceholder) {
    jqDropDown.prop("disabled", true);

    if (currentValue == null)
        currentValue = "";

    if (currentValue.length == 0) {
        jqDropDown.html("<option selected></option>");
    }
    else {
        jqDropDown.html("<option></option><option selected>" + htmlEncode(currentValue) + "</option>");
        jqDropDown.val(currentValue);
    }

    var node = $("#optZonesClusterNode").val();

    HTTPRequest({
        url: "api/settings/getTsigKeyNames?token=" + sessionData.token + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            loadTsigKeyNamesFrom(responseJSON.response.tsigKeyNames, jqDropDown, currentValue);
        },
        error: function () {
            jqDropDown.prop("disabled", false);
        },
        invalidToken: function () {
            jqDropDown.prop("disabled", false);
            showPageLogin();
        },
        objAlertPlaceholder: divAlertPlaceholder
    });
}

function loadTsigKeyNamesFrom(tsigKeyNames, jqDropDown, currentValue) {
    var optionsHtml;

    if ((currentValue == null) || (currentValue.length == 0))
        optionsHtml = "<option selected></option>";
    else
        optionsHtml = "<option></option>";

    for (var i = 0; i < tsigKeyNames.length; i++) {
        optionsHtml += "<option" + (tsigKeyNames[i] === currentValue ? " selected" : "") + ">" + htmlEncode(tsigKeyNames[i]) + "</option>";
    }

    jqDropDown.html(optionsHtml);
    jqDropDown.prop("disabled", false);
}

function updateAddZoneFormForwarderThisServer() {
    var useThisServer = $("#chkAddZoneForwarderThisServer").prop('checked');

    if (useThisServer) {
        $("input[name=rdAddZoneForwarderProtocol]:radio").attr("disabled", true);
        $("#rdAddZoneForwarderProtocolUdp").prop("checked", true);
        $("#txtAddZoneForwarder").attr("placeholder", "8.8.8.8 or [2620:fe::10]")

        $("#txtAddZoneForwarder").prop("disabled", true);
        $("#txtAddZoneForwarder").val("this-server");

        $("#divAddZoneForwarderProxy").hide();
    }
    else {
        $("input[name=rdAddZoneForwarderProtocol]:radio").attr("disabled", false);

        $("#txtAddZoneForwarder").prop("disabled", false);
        $("#txtAddZoneForwarder").val("");

        $("#divAddZoneForwarderProxy").show();
    }
}

function addZone() {
    var divAddZoneAlert = $("#divAddZoneAlert");
    var zone = $("#txtAddZone").val();

    if ((zone == null) || (zone === "")) {
        showAlert("warning", "Missing!", "Please enter a domain name to add zone.", divAddZoneAlert);
        $("#txtAddZone").trigger("focus");
        return;
    }

    var type = $('input[name=rdAddZoneType]:checked').val();

    var parameters;

    switch (type) {
        case "Primary":
            var catalog = $("#optAddZoneCatalogZoneName").val();
            var useSoaSerialDateScheme = $("#chkAddZoneUseSoaSerialDateScheme").prop("checked");

            parameters = "&catalog=" + catalog + "&useSoaSerialDateScheme=" + useSoaSerialDateScheme;
            break;

        case "Secondary":
            parameters = "&primaryNameServerAddresses=" + encodeURIComponent(cleanTextList($("#txtAddZonePrimaryNameServerAddresses").val()));
            parameters += "&zoneTransferProtocol=" + $("input[name=rdAddZoneZoneTransferProtocol]:checked").val();
            parameters += "&tsigKeyName=" + encodeURIComponent($("#optAddZoneTsigKeyName").val());
            parameters += "&validateZone=" + $("#chkAddZoneValidateZone").prop("checked");
            break;

        case "Stub":
            var catalog = $("#optAddZoneCatalogZoneName").val();

            parameters = "&catalog=" + catalog + "&primaryNameServerAddresses=" + encodeURIComponent(cleanTextList($("#txtAddZonePrimaryNameServerAddresses").val()));
            break;

        case "Forwarder":
            var catalog = $("#optAddZoneCatalogZoneName").val();
            var initializeForwarder = $("#chkAddZoneInitializeForwarder").prop("checked");

            if (initializeForwarder) {
                var protocol = $("input[name=rdAddZoneForwarderProtocol]:checked").val();

                var forwarder = $("#txtAddZoneForwarder").val();
                if ((forwarder == null) || (forwarder === "")) {
                    showAlert("warning", "Missing!", "Please enter a forwarder server address to add zone.", divAddZoneAlert);
                    $("#txtAddZoneForwarder").trigger("focus");
                    return;
                }

                var dnssecValidation = $("#chkAddZoneForwarderDnssecValidation").prop("checked");

                parameters = "&catalog=" + catalog + "&protocol=" + protocol + "&forwarder=" + encodeURIComponent(forwarder) + "&dnssecValidation=" + dnssecValidation;

                if (forwarder !== "this-server") {
                    var proxyType = $("input[name=rdAddZoneForwarderProxyType]:checked").val();

                    parameters += "&proxyType=" + proxyType;

                    switch (proxyType) {
                        case "Http":
                        case "Socks5":
                            var proxyAddress = $("#txtAddZoneForwarderProxyAddress").val();
                            var proxyPort = $("#txtAddZoneForwarderProxyPort").val();
                            var proxyUsername = $("#txtAddZoneForwarderProxyUsername").val();
                            var proxyPassword = $("#txtAddZoneForwarderProxyPassword").val();

                            if ((proxyAddress == null) || (proxyAddress === "")) {
                                showAlert("warning", "Missing!", "Please enter a domain name or IP address for Proxy Server Address to add zone.", divAddZoneAlert);
                                $("#txtAddZoneForwarderProxyAddress").trigger("focus");
                                return;
                            }

                            if ((proxyPort == null) || (proxyPort === "")) {
                                showAlert("warning", "Missing!", "Please enter a port number for Proxy Server Port to add zone.", divAddZoneAlert);
                                $("#txtAddZoneForwarderProxyPort").trigger("focus");
                                return;
                            }

                            parameters += "&proxyAddress=" + encodeURIComponent(proxyAddress) + "&proxyPort=" + proxyPort + "&proxyUsername=" + encodeURIComponent(proxyUsername) + "&proxyPassword=" + encodeURIComponent(proxyPassword);
                            break;
                    }
                }

                parameters += "&initializeForwarder=true";
            } else {
                parameters = "&initializeForwarder=false";
            }

            break;

        case "SecondaryForwarder":
        case "SecondaryCatalog":
            var primaryNameServerAddresses = cleanTextList($("#txtAddZonePrimaryNameServerAddresses").val());
            if ((primaryNameServerAddresses.length === 0) || (primaryNameServerAddresses === ",")) {
                showAlert("warning", "Missing!", "Please enter at least one primary name server address to proceed.", divAddZoneAlert);
                $("#txtAddZonePrimaryNameServerAddresses").trigger("focus");
                return;
            }

            parameters = "&primaryNameServerAddresses=" + encodeURIComponent(primaryNameServerAddresses);
            parameters += "&zoneTransferProtocol=" + $("input[name=rdAddZoneZoneTransferProtocol]:checked").val();
            parameters += "&tsigKeyName=" + encodeURIComponent($("#optAddZoneTsigKeyName").val());
            break;

        case "SecondaryRoot":
            type = "Secondary";
            parameters = "&primaryNameServerAddresses=199.9.14.201,192.33.4.12,199.7.91.13,192.5.5.241,192.112.36.4,193.0.14.129,192.0.47.132,192.0.32.132,[2001:500:200::b],[2001:500:2::c],[2001:500:2d::d],[2001:500:2f::f],[2001:500:12::d0d],[2001:7fd::1],[2620:0:2830:202::132],[2620:0:2d0:202::132]";
            parameters += "&zoneTransferProtocol=Tcp";
            parameters += "&validateZone=true";
            break;

        default:
            parameters = "";
            break;
    }

    var formData;

    switch (type) {
        case "Primary":
        case "Forwarder":
            var fileAddZoneImportZone = $("#fileAddZoneImportZone");

            if (fileAddZoneImportZone[0].files.length > 0) {
                formData = new FormData();
                formData.append("fileImportZone", fileAddZoneImportZone[0].files[0]);
            }
            break;
    }

    var node = $("#optZonesClusterNode").val();

    var btn = $("#btnAddZone");
    btn.button("loading");

    HTTPRequest({
        url: "api/zones/create?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&type=" + type + parameters + "&node=" + encodeURIComponent(node),
        method: "POST",
        data: formData,
        contentType: false,
        processData: false,
        success: function (responseJSON) {
            $("#modalAddZone").modal("hide");
            showEditZone(responseJSON.response.domain);

            showAlert("success", "Zone Added!", "Zone was added successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalAddZone").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divAddZoneAlert
    });
}

function toggleHideDnssecRecords(hideDnssecRecords) {
    localStorage.setItem("zoneHideDnssecRecords", hideDnssecRecords);
    showEditZone($("#titleEditZone").attr("data-zone"));
}

function showEditZone(zone, showPageNumber, zoneFilterName, zoneFilterType) {
    if (zone == null) {
        zone = $("#txtZonesEdit").val();
        if (zone === "") {
            showAlert("warning", "Missing!", "Please enter a zone name to start editing.");
            $("#txtZonesEdit").trigger("focus");
            return;
        }
    }

    if (showPageNumber == null)
        showPageNumber = 1;

    if (zoneFilterName == null)
        zoneFilterName = "";

    if (zoneFilterType == null)
        zoneFilterType = "";

    var node = $("#optZonesClusterNode").val();

    var divViewZonesLoader = $("#divViewZonesLoader");
    var divViewZones = $("#divViewZones");
    var divEditZone = $("#divEditZone");

    divViewZones.hide();
    divEditZone.hide();
    divViewZonesLoader.show();

    HTTPRequest({
        url: "api/zones/records/get?token=" + sessionData.token + "&domain=" + encodeURIComponent(zone) + "&zone=" + encodeURIComponent(zone) + "&listZone=true" + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            zone = responseJSON.response.zone.name;
            if (zone === "")
                zone = ".";

            var zoneType;
            if (responseJSON.response.zone.internal)
                zoneType = "Internal";
            else
                zoneType = responseJSON.response.zone.type;

            switch (responseJSON.response.zone.dnssecStatus) {
                case "SignedWithNSEC":
                case "SignedWithNSEC3":
                    $("#titleEditZoneDnssecStatus").removeClass();

                    if (responseJSON.response.zone.hasDnssecPrivateKeys)
                        $("#titleEditZoneDnssecStatus").addClass("label label-primary");
                    else
                        $("#titleEditZoneDnssecStatus").addClass("label label-default");

                    $("#titleEditZoneDnssecStatus").show();
                    break;

                default:
                    $("#titleEditZoneDnssecStatus").hide();
                    break;
            }

            var status;
            if (responseJSON.response.zone.disabled)
                status = "Disabled";
            else if (responseJSON.response.zone.isExpired)
                status = "Expired";
            else if (responseJSON.response.zone.validationFailed)
                status = "Validation Failed";
            else if (responseJSON.response.zone.syncFailed)
                status = "Sync Failed";
            else if (responseJSON.response.zone.notifyFailed)
                status = "Notify Failed";
            else
                status = "Enabled";

            if (responseJSON.response.zone.catalog != null) {
                $("#titleEditZoneCatalog").attr("class", "label label-default");
                $("#titleEditZoneCatalog").text(responseJSON.response.zone.catalog);
                $("#titleEditZoneCatalog").show();
            }
            else {
                switch (zoneType) {
                    case "Catalog":
                    case "SecondaryCatalog":
                        $("#titleEditZoneCatalog").attr("class", "label label-info");
                        $("#titleEditZoneCatalog").text(zone);
                        $("#titleEditZoneCatalog").show();
                        break;

                    default:
                        $("#titleEditZoneCatalog").hide();
                        $("#titleEditZoneCatalog").text("");
                        break;
                }
            }

            var expiry = responseJSON.response.zone.expiry;
            if (expiry == null)
                expiry = "&nbsp;";
            else
                expiry = "Expiry: " + moment(expiry).local().format("YYYY-MM-DD HH:mm:ss");

            switch (zoneType) {
                case "SecondaryForwarder":
                    $("#titleEditZoneType").html("Secondary Forwarder");
                    break;

                case "SecondaryCatalog":
                    $("#titleEditZoneType").html("Secondary Catalog");
                    break;

                default:
                    $("#titleEditZoneType").html(zoneType);
                    break;
            }

            $("#titleEditZoneStatus").html(status);
            $("#titleEditZoneExpiry").html(expiry);

            if (responseJSON.response.zone.internal)
                $("#titleEditZoneType").attr("class", "label label-default");
            else
                $("#titleEditZoneType").attr("class", "label label-primary");

            switch (status) {
                case "Disabled":
                case "Sync Failed":
                case "Notify Failed":
                    $("#titleEditZoneStatus").attr("class", "label label-warning");
                    break;

                case "Expired":
                case "Validation Failed":
                    $("#titleEditZoneStatus").attr("class", "label label-danger");
                    break;

                default:
                    $("#titleEditZoneStatus").attr("class", "label label-success");
                    break;
            }

            switch (zoneType) {
                case "Internal":
                case "Secondary":
                case "SecondaryForwarder":
                case "SecondaryCatalog":
                case "Stub":
                case "Catalog":
                    $("#btnEditZoneAddRecord").hide();
                    break;

                case "Forwarder":
                    $("#btnEditZoneAddRecord").show();
                    $("#optAddEditRecordTypeDs").hide();
                    $("#optAddEditRecordTypeSshfp").hide();
                    $("#optAddEditRecordTypeTlsa").hide();
                    $("#optAddEditRecordTypeAName").show();
                    $("#optAddEditRecordTypeFwd").show();
                    $("#optAddEditRecordTypeApp").show();
                    break;

                case "Primary":
                    $("#btnEditZoneAddRecord").show();
                    $("#optAddEditRecordTypeFwd").hide();

                    switch (responseJSON.response.zone.dnssecStatus) {
                        case "SignedWithNSEC":
                        case "SignedWithNSEC3":
                            $("#optAddEditRecordTypeDs").show();
                            $("#optAddEditRecordTypeSshfp").show();
                            $("#optAddEditRecordTypeTlsa").show();
                            $("#optAddEditRecordTypeAName").hide();
                            $("#optAddEditRecordTypeApp").hide();
                            break;

                        default:
                            $("#optAddEditRecordTypeDs").hide();
                            $("#optAddEditRecordTypeSshfp").hide();
                            $("#optAddEditRecordTypeTlsa").hide();
                            $("#optAddEditRecordTypeAName").show();
                            $("#optAddEditRecordTypeApp").show();
                            break;
                    }
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

            switch (zoneType) {
                case "Secondary":
                case "SecondaryForwarder":
                case "SecondaryCatalog":
                case "Stub":
                    $("#btnZoneResync").show();
                    break;

                default:
                    $("#btnZoneResync").hide();
                    break;
            }

            switch (zoneType) {
                case "Primary":
                case "Secondary":
                case "SecondaryForwarder":
                case "SecondaryCatalog":
                case "Stub":
                case "Forwarder":
                case "Catalog":
                    $("#divOptionsMenu").show();
                    break;

                default:
                    $("#divOptionsMenu").hide();
                    break;
            }

            switch (zoneType) {
                case "Primary":
                case "Forwarder":
                    $("#lnkImportZone").show();
                    $("#lnkExportZone").show();
                    break;

                case "Secondary":
                case "SecondaryForwarder":
                case "SecondaryCatalog":
                case "Catalog":
                    $("#lnkImportZone").hide();
                    $("#lnkExportZone").show();
                    break;

                default:
                    $("#lnkImportZone").hide();
                    $("#lnkExportZone").hide();
                    break;
            }

            switch (zoneType) {
                case "Primary":
                case "Secondary":
                case "SecondaryForwarder":
                case "Forwarder":
                case "SecondaryCatalog":
                    $("#lnkZoneConvert").show();
                    break;

                default:
                    $("#lnkZoneConvert").hide();
                    break;
            }

            switch (zoneType) {
                case "Primary":
                case "Forwarder":
                    $("#lnkCloneZone").show();
                    break;

                default:
                    $("#lnkCloneZone").hide();
                    break;
            }

            switch (zoneType) {
                case "Primary":
                case "Secondary":
                case "SecondaryForwarder":
                case "SecondaryCatalog":
                case "Stub":
                case "Forwarder":
                case "Catalog":
                    $("#lnkZoneOptions").show();
                    break;

                default:
                    $("#lnkZoneOptions").hide();
                    break;
            }

            switch (zoneType) {
                case "Primary":
                case "Secondary":
                case "SecondaryForwarder":
                case "SecondaryCatalog":
                case "Stub":
                case "Forwarder":
                case "Catalog":
                    $("#btnZonePermissions").show();
                    break;

                default:
                    $("#btnZonePermissions").hide();
                    break;
            }

            var zoneHideDnssecRecords = (localStorage.getItem("zoneHideDnssecRecords") == "true");

            switch (zoneType) {
                case "Primary":
                    $("#divZoneDnssecOptions").show();

                    switch (responseJSON.response.zone.dnssecStatus) {
                        case "SignedWithNSEC":
                        case "SignedWithNSEC3":
                            $("#lnkZoneDnssecSignZone").hide();

                            if (zoneHideDnssecRecords) {
                                $("#lnkZoneDnssecHideRecords").hide();
                                $("#lnkZoneDnssecShowRecords").show();
                            }
                            else {
                                $("#lnkZoneDnssecHideRecords").show();
                                $("#lnkZoneDnssecShowRecords").hide();
                            }

                            $("#lnkZoneDnssecViewDsRecords").show();
                            $("#lnkZoneDnssecProperties").show();
                            $("#lnkZoneDnssecUnsignZone").show();
                            break;

                        default:
                            $("#lnkZoneDnssecSignZone").show();
                            $("#lnkZoneDnssecHideRecords").hide();
                            $("#lnkZoneDnssecShowRecords").hide();
                            $("#lnkZoneDnssecViewDsRecords").hide();
                            $("#lnkZoneDnssecProperties").hide();
                            $("#lnkZoneDnssecUnsignZone").hide();
                            break;
                    }
                    break;

                case "Secondary":
                    switch (responseJSON.response.zone.dnssecStatus) {
                        case "SignedWithNSEC":
                        case "SignedWithNSEC3":
                            $("#divZoneDnssecOptions").show();

                            $("#lnkZoneDnssecSignZone").hide();

                            if (zoneHideDnssecRecords) {
                                $("#lnkZoneDnssecHideRecords").hide();
                                $("#lnkZoneDnssecShowRecords").show();
                            }
                            else {
                                $("#lnkZoneDnssecHideRecords").show();
                                $("#lnkZoneDnssecShowRecords").hide();
                            }

                            $("#lnkZoneDnssecViewDsRecords").hide();
                            $("#lnkZoneDnssecProperties").hide();
                            $("#lnkZoneDnssecUnsignZone").hide();
                            break;

                        default:
                            $("#divZoneDnssecOptions").hide();
                            break;
                    }
                    break;

                default:
                    $("#divZoneDnssecOptions").hide();
                    break;
            }

            editZoneInfo = responseJSON.response.zone;

            if (!zoneHideDnssecRecords || (responseJSON.response.zone.dnssecStatus === "Unsigned")) {
                editZoneRecords = responseJSON.response.records;
            }
            else {
                var records = responseJSON.response.records;
                editZoneRecords = [];

                for (var i = 0; i < records.length; i++) {
                    switch (records[i].type.toUpperCase()) {
                        case "RRSIG":
                        case "NSEC":
                        case "DNSKEY":
                        case "NSEC3":
                        case "NSEC3PARAM":
                            continue;

                        default:
                            editZoneRecords.push(records[i]);
                            break;
                    }
                }
            }

            $("#optEditZoneClusterNode").val(node);

            if (responseJSON.response.zone.nameIdn == null)
                $("#titleEditZone").text(zone === "." ? "<root>" : zone);
            else
                $("#titleEditZone").text(responseJSON.response.zone.nameIdn + " (" + zone + ")");

            $("#titleEditZone").attr("data-zone", zone);
            $("#titleEditZone").attr("data-zone-type", zoneType);

            $("#txtEditZoneFilterName").val(zoneFilterName);
            $("#txtEditZoneFilterType").val(zoneFilterType);
            editZoneFilteredRecords = null; //to evaluate filters again

            showEditZonePage(showPageNumber);

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

function showEditZonePage(pageNumber) {
    var filterName = $("#txtEditZoneFilterName").val();
    if (filterName === "")
        filterName = null;

    var filterType = $("#txtEditZoneFilterType").val();
    if (filterType === "")
        filterType = null;

    if (pageNumber == null)
        pageNumber = Number($("#txtEditZonePageNumber").val());

    if (pageNumber == 0)
        pageNumber = 1;

    var recordsPerPage = Number($("#optEditZoneRecordsPerPage").val());
    if (recordsPerPage < 1)
        recordsPerPage = 10;

    var zone = $("#titleEditZone").attr("data-zone");
    var zoneType = $("#titleEditZone").attr("data-zone-type");

    if (editZoneFilteredRecords == null) {
        if ((filterName != null) || (filterType != null)) {
            editZoneFilteredRecords = [];
            var filterDomain = null;
            var filterRegex = null;

            if (filterName != null) {
                filterDomain = filterName.toLowerCase();

                if (zone == ".") {
                    if (filterDomain === "@")
                        filterDomain = "";
                }
                else {
                    if (filterDomain === "@")
                        filterDomain = zone;
                    else
                        filterDomain += "." + zone;
                }

                if ((filterName.indexOf("*") > -1) || (filterName.indexOf("?") > -1)) {
                    filterDomain = filterDomain.replace(/\./g, "\\\.");
                    filterDomain = filterDomain.replace(/\*/g, ".*");
                    filterDomain = filterDomain.replace(/\?/g, ".");

                    if (filterDomain.startsWith(".*\\\."))
                        filterDomain = "\\\*" + filterDomain.substring(2);

                    filterRegex = new RegExp("^" + filterDomain + "$");
                }
            }

            if (filterType != null)
                filterType = filterType.toUpperCase();

            for (var i = 0; i < editZoneRecords.length; i++) {
                if (filterRegex == null) {
                    if ((filterDomain != null) && (editZoneRecords[i].name.toLowerCase() !== filterDomain))
                        continue;
                }
                else if (!filterRegex.test(editZoneRecords[i].name.toLowerCase())) {
                    continue;
                }

                if ((filterType != null) && (editZoneRecords[i].type !== filterType))
                    continue;

                editZoneRecords[i].index = i; //keep original index for update tasks

                editZoneFilteredRecords.push(editZoneRecords[i]);
            }
        }
        else {
            for (var i = 0; i < editZoneRecords.length; i++)
                editZoneRecords[i].index = i; //keep original index for update tasks

            editZoneFilteredRecords = editZoneRecords;
        }
    }

    var totalRecords = editZoneFilteredRecords.length;
    var totalPages = Math.floor(totalRecords / recordsPerPage) + (totalRecords % recordsPerPage > 0 ? 1 : 0);

    if ((pageNumber > totalPages) || (pageNumber < 0))
        pageNumber = totalPages;

    if (pageNumber < 1)
        pageNumber = 1;

    var start = (pageNumber - 1) * recordsPerPage;
    var end = Math.min(start + recordsPerPage, totalRecords);

    var tableHtmlRows = "";

    for (var i = start; i < end; i++)
        tableHtmlRows += getZoneRecordRowHtml(i, zone, zoneType, editZoneFilteredRecords[i]);

    var paginationHtml = "";

    if (pageNumber > 1) {
        paginationHtml += "<li><a href=\"#\" aria-label=\"First\" onClick=\"showEditZonePage(1); return false;\"><span aria-hidden=\"true\">&laquo;</span></a></li>";
        paginationHtml += "<li><a href=\"#\" aria-label=\"Previous\" onClick=\"showEditZonePage(" + (pageNumber - 1) + "); return false;\"><span aria-hidden=\"true\">&lsaquo;</span></a></li>";
    }

    var pageStart = pageNumber - 5;
    if (pageStart < 1)
        pageStart = 1;

    var pageEnd = pageStart + 9;
    if (pageEnd > totalPages) {
        var endDiff = pageEnd - totalPages;
        pageEnd = totalPages;

        pageStart -= endDiff;
        if (pageStart < 1)
            pageStart = 1;
    }

    for (var i = pageStart; i <= pageEnd; i++) {
        if (i == pageNumber)
            paginationHtml += "<li class=\"active\"><a href=\"#\" onClick=\"showEditZonePage(" + i + "); return false;\">" + i + "</a></li>";
        else
            paginationHtml += "<li><a href=\"#\" onClick=\"showEditZonePage(" + i + "); return false;\">" + i + "</a></li>";
    }

    if (pageNumber < totalPages) {
        paginationHtml += "<li><a href=\"#\" aria-label=\"Next\" onClick=\"showEditZonePage(" + (pageNumber + 1) + "); return false;\"><span aria-hidden=\"true\">&rsaquo;</span></a></li>";
        paginationHtml += "<li><a href=\"#\" aria-label=\"Last\" onClick=\"showEditZonePage(-1); return false;\"><span aria-hidden=\"true\">&raquo;</span></a></li>";
    }

    var statusHtml;

    if (editZoneFilteredRecords.length > 0)
        statusHtml = (start + 1) + "-" + end + " (" + (end - start) + ") of " + editZoneFilteredRecords.length + " records (page " + pageNumber + " of " + totalPages + ")";
    else
        statusHtml = "0 records";

    $("#txtEditZonePageNumber").val(pageNumber);
    $("#tableEditZoneBody").html(tableHtmlRows);

    $("#tableEditZoneTopStatus").html(statusHtml);
    $("#tableEditZoneTopPagination").html(paginationHtml);

    $("#tableEditZoneFooterStatus").html(statusHtml);
    $("#tableEditZoneFooterPagination").html(paginationHtml);
}

function getZoneRecordRowHtml(index, zone, zoneType, record) {
    var name = record.name;
    if (name === "")
        name = ".";

    var lowerName = name.toLowerCase();

    if (lowerName === zone) {
        name = "@";
    } else {
        var i = lowerName.lastIndexOf("." + zone)
        if (i > -1)
            name = name.substring(0, i);
    }

    var tableHtmlRow = "<tr id=\"trZoneRecord" + index + "\"><td>" + (index + 1) + "</td><td>" + htmlEncode(name) + "</td>";
    tableHtmlRow += "<td>" + record.type + "</td>";
    tableHtmlRow += "<td>" + record.ttl + "<br />(" + record.ttlString + ")</td>";

    var additionalDataAttributes = "";

    tableHtmlRow += "<td style=\"word-break: break-all;\">";

    switch (record.type.toUpperCase()) {
        case "A":
        case "AAAA":
            tableHtmlRow += htmlEncode(record.rData.ipAddress);
            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-ip-address=\"" + htmlEncode(record.rData.ipAddress) + "\" ";
            break;

        case "NS":
            var notifyFailed = false;

            if (editZoneInfo.notifyFailedFor != null) {
                for (var i = 0; i < editZoneInfo.notifyFailedFor.length; i++) {
                    if (editZoneInfo.notifyFailedFor[i] == record.rData.nameServer) {
                        notifyFailed = true;
                        break;
                    }
                }
            }

            tableHtmlRow += "<b>Name Server:</b> " + htmlEncode(record.rData.nameServer);

            if (notifyFailed)
                tableHtmlRow += "<span class=\"label label-warning\" style=\"margin-left: 8px;\">Notify Failed</span>";

            if (record.glueRecords != null) {
                var glue = null;

                for (var i = 0; i < record.glueRecords.length; i++) {
                    if (i == 0)
                        glue = record.glueRecords[i];
                    else
                        glue += ", " + record.glueRecords[i];
                }

                tableHtmlRow += "<br /><b>Glue Addresses:</b> " + glue;

                additionalDataAttributes = "data-record-glue=\"" + htmlEncode(glue) + "\" ";
            } else {
                additionalDataAttributes = "data-record-glue=\"\" ";
            }

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes += "data-record-name-server=\"" + htmlEncode(record.rData.nameServer) + "\" ";
            break;

        case "CNAME":
            tableHtmlRow += htmlEncode(record.rData.cname);
            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-cname=\"" + htmlEncode(record.rData.cname) + "\" ";
            break;

        case "SOA":
            tableHtmlRow += "<b>Primary Name Server:</b> " + htmlEncode(record.rData.primaryNameServer) +
                "<br /><b>Responsible Person:</b> " + htmlEncode(record.rData.responsiblePerson) +
                "<br /><b>Serial:</b> " + htmlEncode(record.rData.serial) +
                "<br /><b>Refresh:</b> " + htmlEncode(record.rData.refresh + " (" + record.rData.refreshString + ")") +
                "<br /><b>Retry:</b> " + htmlEncode(record.rData.retry + " (" + record.rData.retryString + ")") +
                "<br /><b>Expire:</b> " + htmlEncode(record.rData.expire + " (" + record.rData.expireString + ")") +
                "<br /><b>Minimum:</b> " + htmlEncode(record.rData.minimum + " (" + record.rData.minimumString + ")");

            if (record.rData.useSerialDateScheme != null) {
                tableHtmlRow += "<br /><br /><b>Use Serial Date Scheme:</b> " + record.rData.useSerialDateScheme;

                additionalDataAttributes = "data-record-serial-scheme=\"" + htmlEncode(record.rData.useSerialDateScheme) + "\" ";
            }
            else {
                additionalDataAttributes = "data-record-serial-scheme=\"false\" ";
            }

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes += "data-record-pname=\"" + htmlEncode(record.rData.primaryNameServer) + "\" " +
                "data-record-rperson=\"" + htmlEncode(record.rData.responsiblePerson) + "\" " +
                "data-record-serial=\"" + htmlEncode(record.rData.serial) + "\" " +
                "data-record-refresh=\"" + htmlEncode(record.rData.refresh) + "\" " +
                "data-record-retry=\"" + htmlEncode(record.rData.retry) + "\" " +
                "data-record-expire=\"" + htmlEncode(record.rData.expire) + "\" " +
                "data-record-minimum=\"" + htmlEncode(record.rData.minimum) + "\" ";
            break;

        case "PTR":
            tableHtmlRow += htmlEncode(record.rData.ptrName);
            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-ptr-name=\"" + htmlEncode(record.rData.ptrName) + "\" ";
            break;

        case "MX":
            tableHtmlRow += "<b>Preference: </b> " + htmlEncode(record.rData.preference) +
                "<br /><b>Exchange:</b> " + htmlEncode(record.rData.exchange);

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-preference=\"" + htmlEncode(record.rData.preference) + "\" " +
                "data-record-exchange=\"" + htmlEncode(record.rData.exchange) + "\" ";
            break;

        case "TXT":
            var text;

            if (record.rData.splitText) {
                for (var i = 0; i < record.rData.characterStrings.length; i++) {
                    var characterString = record.rData.characterStrings[i].replace(/\\/g, "\\\\").replace(/\r/g, "\\r").replace(/\n/g, "\\n");

                    tableHtmlRow += "\"" + htmlEncode(characterString.replace(/"/g, "\\\"")) + "\"<br />";

                    if (text == null)
                        text = characterString;
                    else
                        text += "\n" + characterString;
                }
            }
            else {
                var characterString = record.rData.text.replace(/\\/g, "\\\\").replace(/\r/g, "\\r").replace(/\n/g, "\\n");
                tableHtmlRow += htmlEncode(characterString.replace(/"/g, "\\\"")) + "<br />";

                text = record.rData.text;
            }

            tableHtmlRow += "<br />";

            additionalDataAttributes = "data-record-text=\"" + htmlEncode(text) + "\" " +
                "data-record-split-text=\"" + htmlEncode(record.rData.splitText) + "\" ";
            break;

        case "RP":
            tableHtmlRow += "<b>Mailbox: </b> " + htmlEncode(record.rData.mailbox) +
                "<br /><b>TXT Domain:</b> " + htmlEncode(record.rData.txtDomain);

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-mailbox=\"" + htmlEncode(record.rData.mailbox) + "\" " +
                "data-record-txt-domain=\"" + htmlEncode(record.rData.txtDomain) + "\" ";
            break;

        case "SRV":
            tableHtmlRow += "<b>Priority: </b> " + htmlEncode(record.rData.priority) +
                "<br /><b>Weight:</b> " + htmlEncode(record.rData.weight) +
                "<br /><b>Port:</b> " + htmlEncode(record.rData.port) +
                "<br /><b>Target:</b> " + htmlEncode(record.rData.target);

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-priority=\"" + htmlEncode(record.rData.priority) + "\" " +
                "data-record-weight=\"" + htmlEncode(record.rData.weight) + "\" " +
                "data-record-port=\"" + htmlEncode(record.rData.port) + "\" " +
                "data-record-target=\"" + htmlEncode(record.rData.target) + "\" ";
            break;

        case "NAPTR":
            tableHtmlRow += "<b>Order: </b> " + htmlEncode(record.rData.order) +
                "<br /><b>Preference:</b> " + htmlEncode(record.rData.preference) +
                "<br /><b>Flags:</b> " + htmlEncode(record.rData.flags) +
                "<br /><b>Services:</b> " + htmlEncode(record.rData.services) +
                "<br /><b>Regular Expression:</b> " + htmlEncode(record.rData.regexp) +
                "<br /><b>Replacement:</b> " + htmlEncode(record.rData.replacement);

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-order=\"" + htmlEncode(record.rData.order) + "\" " +
                "data-record-preference=\"" + htmlEncode(record.rData.preference) + "\" " +
                "data-record-flags=\"" + htmlEncode(record.rData.flags) + "\" " +
                "data-record-services=\"" + htmlEncode(record.rData.services) + "\" " +
                "data-record-regexp=\"" + htmlEncode(record.rData.regexp) + "\" " +
                "data-record-replacement=\"" + htmlEncode(record.rData.replacement) + "\" ";
            break;

        case "DNAME":
            tableHtmlRow += htmlEncode(record.rData.dname);
            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-dname=\"" + htmlEncode(record.rData.dname) + "\" ";
            break;

        case "APL":
            tableHtmlRow += "<table class=\"table\" style=\"background: transparent;\"><thead><tr><th>Family</th><th>Negation</th><th>AFD Part</th><th>Prefix</th></tr></thead><tbody>";

            for (var i = 0; i < record.rData.addressPrefixes.length; i++) {
                tableHtmlRow += "<tr><td>" + record.rData.addressPrefixes[i].addressFamily + "</td>";
                tableHtmlRow += "<td>" + record.rData.addressPrefixes[i].negation + "</td>";
                tableHtmlRow += "<td>" + record.rData.addressPrefixes[i].afdPart + "</td>";
                tableHtmlRow += "<td>" + record.rData.addressPrefixes[i].prefix + "</td></tr>";
            }

            tableHtmlRow += "</tbody></table>";

            additionalDataAttributes = "";
            break;

        case "DS":
            tableHtmlRow += "<b>Key Tag: </b> " + htmlEncode(record.rData.keyTag) +
                "<br /><b>Algorithm:</b> " + htmlEncode(record.rData.algorithm + " (" + record.rData.algorithmNumber + ")") +
                "<br /><b>Digest Type:</b> " + htmlEncode(record.rData.digestType + " (" + record.rData.digestTypeNumber + ")") +
                "<br /><b>Digest:</b> " + htmlEncode(record.rData.digest);

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-key-tag=\"" + htmlEncode(record.rData.keyTag) + "\" " +
                "data-record-algorithm=\"" + htmlEncode(record.rData.algorithm) + "\" " +
                "data-record-digest-type=\"" + htmlEncode(record.rData.digestType) + "\" " +
                "data-record-digest=\"" + htmlEncode(record.rData.digest) + "\" ";
            break;

        case "SSHFP":
            tableHtmlRow += "<b>Algorithm:</b> " + htmlEncode(record.rData.algorithm) +
                "<br /><b>Fingerprint Type:</b> " + htmlEncode(record.rData.fingerprintType) +
                "<br /><b>Fingerprint:</b> " + htmlEncode(record.rData.fingerprint);

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-algorithm=\"" + htmlEncode(record.rData.algorithm) + "\" " +
                "data-record-fingerprint-type=\"" + htmlEncode(record.rData.fingerprintType) + "\" " +
                "data-record-fingerprint=\"" + htmlEncode(record.rData.fingerprint) + "\" ";
            break;

        case "RRSIG":
            tableHtmlRow += "<b>Type Covered: </b> " + htmlEncode(record.rData.typeCovered) +
                "<br /><b>Algorithm:</b> " + htmlEncode(record.rData.algorithm + " (" + record.rData.algorithmNumber + ")") +
                "<br /><b>Labels:</b> " + htmlEncode(record.rData.labels) +
                "<br /><b>Original TTL:</b> " + htmlEncode(record.rData.originalTtl) +
                "<br /><b>Signature Expiration:</b> " + moment(record.rData.signatureExpiration).local().format("YYYY-MM-DD HH:mm:ss") +
                "<br /><b>Signature Inception:</b> " + moment(record.rData.signatureInception).local().format("YYYY-MM-DD HH:mm:ss") +
                "<br /><b>Key Tag:</b> " + htmlEncode(record.rData.keyTag) +
                "<br /><b>Signer's Name:</b> " + htmlEncode(record.rData.signersName) +
                "<br /><b>Signature:</b> " + htmlEncode(record.rData.signature);

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "";
            break;

        case "NSEC":
            var nsecTypes = null;

            for (var j = 0; j < record.rData.types.length; j++) {
                if (nsecTypes == null)
                    nsecTypes = record.rData.types[j];
                else
                    nsecTypes += ", " + record.rData.types[j];
            }

            tableHtmlRow += "<b>Next Domain Name: </b> " + htmlEncode(record.rData.nextDomainName) +
                "<br /><b>Types:</b> " + htmlEncode(nsecTypes);

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "";
            break;

        case "DNSKEY":
            tableHtmlRow += "<b>Flags: </b> " + htmlEncode(record.rData.flags) +
                "<br /><b>Protocol:</b> " + htmlEncode(record.rData.protocol) +
                "<br /><b>Algorithm:</b> " + htmlEncode(record.rData.algorithm + " (" + record.rData.algorithmNumber + ")") +
                "<br /><b>Public Key:</b> " + htmlEncode(record.rData.publicKey);

            if (record.rData.dnsKeyState == null) {
                tableHtmlRow += "<br />";
            }
            else {
                if (record.rData.dnsKeyStateReadyBy != null)
                    tableHtmlRow += "<br /><br /><b>Key State:</b> " + htmlEncode(record.rData.dnsKeyState) + " (ready by: " + moment(record.rData.dnsKeyStateReadyBy).local().format("YYYY-MM-DD HH:mm") + ")";
                else if (record.rData.dnsKeyStateActiveBy != null)
                    tableHtmlRow += "<br /><br /><b>Key State:</b> " + htmlEncode(record.rData.dnsKeyState) + " (active by: " + moment(record.rData.dnsKeyStateActiveBy).local().format("YYYY-MM-DD HH:mm") + ")";
                else
                    tableHtmlRow += "<br /><br /><b>Key State:</b> " + htmlEncode(record.rData.dnsKeyState);
            }

            tableHtmlRow += "<br /><b>Computed Key Tag:</b> " + htmlEncode(record.rData.computedKeyTag);

            if (record.rData.computedDigests != null) {
                tableHtmlRow += "<br /><b>Computed Digests:</b> ";

                for (var j = 0; j < record.rData.computedDigests.length; j++) {
                    tableHtmlRow += "<br />" + htmlEncode(record.rData.computedDigests[j].digestType) + ": " + htmlEncode(record.rData.computedDigests[j].digest)
                }
            }

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "";
            break;

        case "NSEC3":
            var nsec3Types = null;

            for (var j = 0; j < record.rData.types.length; j++) {
                if (nsec3Types == null)
                    nsec3Types = record.rData.types[j];
                else
                    nsec3Types += ", " + record.rData.types[j];
            }

            tableHtmlRow += "<b>Hash Algorithm: </b> " + htmlEncode(record.rData.hashAlgorithm) +
                "<br /><b>Flags: </b> " + htmlEncode(record.rData.flags) +
                "<br /><b>Iterations: </b> " + htmlEncode(record.rData.iterations) +
                "<br /><b>Salt: </b>" + htmlEncode(record.rData.salt) +
                "<br /><b>Next Hashed Owner Name: </b> " + htmlEncode(record.rData.nextHashedOwnerName) +
                "<br /><b>Types:</b> " + htmlEncode(nsec3Types);

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "";
            break;

        case "NSEC3PARAM":
            tableHtmlRow += "<b>Hash Algorithm: </b> " + htmlEncode(record.rData.hashAlgorithm) +
                "<br /><b>Flags: </b> " + htmlEncode(record.rData.flags) +
                "<br /><b>Iterations: </b> " + htmlEncode(record.rData.iterations) +
                "<br /><b>Salt: </b>" + htmlEncode(record.rData.salt);

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "";
            break;

        case "TLSA":
            tableHtmlRow += "<b>Certificate Usage: </b> " + htmlEncode(record.rData.certificateUsage) +
                "<br /><b>Selector: </b> " + htmlEncode(record.rData.selector) +
                "<br /><b>Matching Type: </b> " + htmlEncode(record.rData.matchingType) +
                "<br /><b>Certificate Association Data:</b> " + (record.rData.certificateAssociationData == "" ? "<br />" : "<pre style=\"white-space: pre-wrap;\">" + htmlEncode(record.rData.certificateAssociationData) + "</pre>");

            tableHtmlRow += "<br />";

            additionalDataAttributes = "data-record-certificate-usage=\"" + htmlEncode(record.rData.certificateUsage) + "\" " +
                "data-record-selector=\"" + htmlEncode(record.rData.selector) + "\" " +
                "data-record-matching-type=\"" + htmlEncode(record.rData.matchingType) + "\" " +
                "data-record-certificate-association-data=\"" + htmlEncode(record.rData.certificateAssociationData) + "\" ";
            break;

        case "ZONEMD":
            tableHtmlRow += "<b>Serial: </b> " + htmlEncode(record.rData.serial) +
                "<br /><b>Scheme: </b> " + htmlEncode(record.rData.scheme) +
                "<br /><b>Hash Algorithm: </b> " + htmlEncode(record.rData.hashAlgorithm) +
                "<br /><b>Digest:</b> " + record.rData.digest;

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "";
            break;

        case "SVCB":
        case "HTTPS":
            var tableHtmlSvcParams;

            if (Object.keys(record.rData.svcParams).length == 0) {
                tableHtmlSvcParams = "<br />";
            }
            else {
                tableHtmlSvcParams = "<br /><b>Params: </b><table class=\"table table-condensed\" style=\"background: transparent; margin-bottom: 0px;\">" +
                    "<thead><tr>" +
                    "<th>Key</th>" +
                    "<th>Value</th>" +
                    "</thead>" +
                    "<tbody>";

                for (var paramKey in record.rData.svcParams) {
                    switch (paramKey) {
                        case "ipv4hint":
                            if (record.rData.autoIpv4Hint)
                                continue;

                            break;

                        case "ipv6hint":
                            if (record.rData.autoIpv6Hint)
                                continue;

                            break;
                    }

                    tableHtmlSvcParams += "<tr><td>" + htmlEncode(paramKey) + "</td><td>" + htmlEncode(record.rData.svcParams[paramKey]) + "</td></tr>";
                }

                tableHtmlSvcParams += "</tbody></table>";
            }

            tableHtmlRow += "<b>Priority: </b> " + htmlEncode(record.rData.svcPriority) + (record.rData.svcPriority == 0 ? " (alias mode)" : " (service mode)") +
                "<br /><b>Target Name: </b> " + (record.rData.svcTargetName == "" ? "." : htmlEncode(record.rData.svcTargetName)) +
                tableHtmlSvcParams +
                "<br /><b>Use Automatic IPv4 Hint: </b> " + record.rData.autoIpv4Hint +
                "<br /><b>Use Automatic IPv6 Hint: </b> " + record.rData.autoIpv6Hint +
                "<br />";

            tableHtmlRow += "<br />";

            additionalDataAttributes = "data-record-svc-priority=\"" + htmlEncode(record.rData.svcPriority) + "\"" +
                "data-record-svc-target-name=\"" + (record.rData.svcTargetName == "" ? "." : htmlEncode(record.rData.svcTargetName)) + "\"" +
                "data-record-svc-params=\"" + htmlEncode(JSON.stringify(record.rData.svcParams)) + "\"" +
                "data-record-auto-ipv4hint=\"" + htmlEncode(record.rData.autoIpv4Hint) + "\"" +
                "data-record-auto-ipv6hint=\"" + htmlEncode(record.rData.autoIpv6Hint) + "\"";
            break;

        case "URI":
            tableHtmlRow += "<b>Priority: </b> " + htmlEncode(record.rData.priority) +
                "<br /><b>Weight:</b> " + htmlEncode(record.rData.weight) +
                "<br /><b>URI:</b> " + htmlEncode(record.rData.uri);

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-priority=\"" + htmlEncode(record.rData.priority) + "\" " +
                "data-record-weight=\"" + htmlEncode(record.rData.weight) + "\" " +
                "data-record-uri=\"" + htmlEncode(record.rData.uri) + "\" ";
            break;

        case "CAA":
            tableHtmlRow += "<b>Flags: </b> " + htmlEncode(record.rData.flags) +
                "<br /><b>Tag:</b> " + htmlEncode(record.rData.tag) +
                "<br /><b>Authority:</b> " + htmlEncode(record.rData.value);

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-flags=\"" + htmlEncode(record.rData.flags) + "\" " +
                "data-record-tag=\"" + htmlEncode(record.rData.tag) + "\" " +
                "data-record-value=\"" + htmlEncode(record.rData.value) + "\" ";
            break;

        case "ANAME":
            tableHtmlRow += "" + htmlEncode(record.rData.aname);
            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-aname=\"" + htmlEncode(record.rData.aname) + "\" ";
            break;

        case "FWD":
            tableHtmlRow += "<b>Protocol: </b> " + htmlEncode(record.rData.protocol) +
                "<br /><b>Forwarder:</b> " + htmlEncode(record.rData.forwarder) +
                "<br /><b>Priority:</b> " + htmlEncode(record.rData.priority) +
                "<br /><b>Enable DNSSEC Validation:</b> " + htmlEncode(record.rData.dnssecValidation) +
                "<br /><b>Proxy Type:</b> " + htmlEncode(record.rData.proxyType);

            switch (record.rData.proxyType) {
                case "Http":
                case "Socks5":
                    tableHtmlRow += "<br /><b>Proxy Address:</b> " + htmlEncode(record.rData.proxyAddress) +
                        "<br /><b>Proxy Port:</b> " + htmlEncode(record.rData.proxyPort) +
                        "<br /><b>Proxy Username:</b> " + htmlEncode(record.rData.proxyUsername) +
                        "<br /><b>Proxy Password:</b> ************";
                    break;
            }

            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-protocol=\"" + htmlEncode(record.rData.protocol) + "\" " +
                "data-record-forwarder=\"" + htmlEncode(record.rData.forwarder) + "\" " +
                "data-record-priority=\"" + htmlEncode(record.rData.priority) + "\" " +
                "data-record-dnssec-validation=\"" + htmlEncode(record.rData.dnssecValidation) + "\" " +
                "data-record-proxy-type=\"" + htmlEncode(record.rData.proxyType) + "\" ";

            switch (record.rData.proxyType) {
                case "Http":
                case "Socks5":
                    additionalDataAttributes += "data-record-proxy-address=\"" + htmlEncode(record.rData.proxyAddress) + "\" " +
                        "data-record-proxy-port=\"" + htmlEncode(record.rData.proxyPort) + "\" " +
                        "data-record-proxy-username=\"" + htmlEncode(record.rData.proxyUsername) + "\" " +
                        "data-record-proxy-password=\"" + htmlEncode(record.rData.proxyPassword) + "\" ";
                    break;
            }
            break;

        case "APP":
            tableHtmlRow += "<b>App Name: </b> " + htmlEncode(record.rData.appName) +
                "<br /><b>Class Path:</b> " + htmlEncode(record.rData.classPath) +
                "<br /><b>Record Data:</b> " + (record.rData.data == "" ? "<br />" : "<pre style=\"white-space: pre-wrap;\">" + htmlEncode(record.rData.data) + "</pre>");

            tableHtmlRow += "<br />";

            additionalDataAttributes = "data-record-app-name=\"" + htmlEncode(record.rData.appName) + "\" " +
                "data-record-classpath=\"" + htmlEncode(record.rData.classPath) + "\" " +
                "data-record-data=\"" + htmlEncode(record.rData.data) + "\"";
            break;

        case "ALIAS":
            tableHtmlRow += "<b>Type: </b> " + htmlEncode(record.rData.type) +
                "<br /><b>Alias:</b> " + htmlEncode(record.rData.alias);

            tableHtmlRow += "<br /><br />";
            break;

        default:
            tableHtmlRow += "<b>RDATA:</b> " + htmlEncode(record.rData.value);
            tableHtmlRow += "<br /><br />";

            additionalDataAttributes = "data-record-rdata=\"" + htmlEncode(record.rData.value) + "\"";
            break;
    }

    if (record.expiryTtl > 0) {
        var expiresOn = moment(record.lastModified).add(record.expiryTtl, "s");
        tableHtmlRow += "<b>Expiry TTL:</b> " + record.expiryTtl + " (" + record.expiryTtlString + ")";
        tableHtmlRow += "<br /><b>Expires On:</b> " + expiresOn.local().format("YYYY-MM-DD HH:mm:ss") + " (" + expiresOn.fromNow() + ")";
        tableHtmlRow += "<br />";
    }

    var lastUsedOn;

    if (record.lastUsedOn == "0001-01-01T00:00:00")
        lastUsedOn = moment(record.lastUsedOn).local().format("YYYY-MM-DD HH:mm:ss") + " (never)";
    else
        lastUsedOn = moment(record.lastUsedOn).local().format("YYYY-MM-DD HH:mm:ss") + " (" + moment(record.lastUsedOn).fromNow() + ")";

    tableHtmlRow += "<b>Last Used:</b> " + lastUsedOn;

    if ((record.lastModified != "0001-01-01T00:00:00") && (record.lastModified != "0001-01-01T00:00:00Z"))
        tableHtmlRow += "<br /><b>Last Modified:</b> " + moment(record.lastModified).local().format("YYYY-MM-DD HH:mm:ss") + " (" + moment(record.lastModified).fromNow() + ")";;

    if ((record.comments != null) && (record.comments.length > 0))
        tableHtmlRow += "<br /><b>Comments:</b> <pre style=\"white-space: pre-wrap;\">" + htmlEncode(record.comments) + "</pre>";

    tableHtmlRow += "</td>";

    var hideActionButtons = false;
    var disableEnableDisableDeleteButtons = false;

    switch (zoneType) {
        case "Internal":
        case "Secondary":
        case "SecondaryForwarder":
        case "SecondaryCatalog":
        case "Stub":
            hideActionButtons = true;
            break;

        case "Catalog":
            switch (record.type) {
                case "SOA":
                    disableEnableDisableDeleteButtons = true;
                    break;

                default:
                    hideActionButtons = true;
                    break;
            }
            break;

        default:
            switch (record.type) {
                case "SOA":
                    disableEnableDisableDeleteButtons = true;
                    break;

                case "DNSKEY":
                case "RRSIG":
                case "NSEC":
                case "NSEC3":
                case "NSEC3PARAM":
                case "ZONEMD":
                    hideActionButtons = true;
                    break;
            }
            break;
    }

    if (hideActionButtons) {
        tableHtmlRow += "<td align=\"right\">&nbsp;</td>";
    }
    else {
        tableHtmlRow += "<td align=\"right\" style=\"min-width: 220px;\">";
        tableHtmlRow += "<div id=\"data" + index + "\" data-record-index=\"" + (record.index == null ? index : record.index) + "\" data-record-name=\"" + htmlEncode(record.name) + "\" data-record-type=\"" + record.type + "\" data-record-ttl=\"" + record.ttl + "\" " + additionalDataAttributes + " data-record-disabled=\"" + record.disabled + "\" data-record-comments=\"" + htmlEncode(record.comments) + "\" data-record-expiry-ttl=\"" + record.expiryTtl + "\" style=\"display: none;\"></div>";
        tableHtmlRow += "<button type=\"button\" class=\"btn btn-primary\" style=\"font-size: 12px; padding: 2px 0px; width: 60px; margin: 0 6px 0 0;\" data-id=\"" + index + "\" onclick=\"showEditRecordModal(this);\">Edit</button>";
        tableHtmlRow += "<button type=\"button\" class=\"btn btn-default\" id=\"btnEnableRecord" + index + "\" style=\"font-size: 12px; padding: 2px 0px; width: 60px; margin: 0 6px 0 0;" + (record.disabled ? "" : " display: none;") + "\" data-id=\"" + index + "\" onclick=\"updateRecordState(this, false);\"" + (disableEnableDisableDeleteButtons ? " disabled" : "") + " data-loading-text=\"Enabling...\">Enable</button>";
        tableHtmlRow += "<button type=\"button\" class=\"btn btn-warning\" id=\"btnDisableRecord" + index + "\" style=\"font-size: 12px; padding: 2px 0px; width: 60px; margin: 0 6px 0 0;" + (!record.disabled ? "" : " display: none;") + "\" data-id=\"" + index + "\" onclick=\"updateRecordState(this, true);\"" + (disableEnableDisableDeleteButtons ? " disabled" : "") + " data-loading-text=\"Disabling...\">Disable</button>";
        tableHtmlRow += "<button type=\"button\" class=\"btn btn-danger\" style=\"font-size: 12px; padding: 2px 0px; width: 60px; margin: 0 6px 0 0;\" data-loading-text=\"Deleting...\" data-id=\"" + index + "\" onclick=\"deleteRecord(this);\"" + (disableEnableDisableDeleteButtons ? " disabled" : "") + ">Delete</button></td>";
    }

    tableHtmlRow += "</tr>";

    return tableHtmlRow;
}

function clearAddEditRecordForm() {
    $("#divAddEditRecordAlert").html("");

    $("#txtAddEditRecordName").prop("placeholder", "@");
    $("#txtAddEditRecordName").prop("disabled", false);
    $("#optAddEditRecordType").prop("disabled", false);
    $("#txtAddEditRecordTtl").prop("disabled", false);

    $("#txtAddEditRecordName").val("");
    $("#optAddEditRecordType").val("A");
    $("#txtAddEditRecordTtl").val("");

    $("#divAddEditRecordData").show();
    $("#divAddEditRecordDataUnknownType").hide();
    $("#txtAddEditRecordDataUnknownType").val("");
    $("#txtAddEditRecordDataUnknownType").prop("disabled", false);
    $("#lblAddEditRecordDataValue").text("IPv4 Address");
    $("#txtAddEditRecordDataValue").val("");
    $("#divAddEditRecordDataPtr").show();
    $("#chkAddEditRecordDataPtr").prop("checked", false);
    $("#chkAddEditRecordDataCreatePtrZone").prop("disabled", true);
    $("#chkAddEditRecordDataCreatePtrZone").prop("checked", false);
    $("#chkAddEditRecordDataPtrLabel").text("Add reverse (PTR) record");

    $("#divAddEditRecordDataNs").hide();
    $("#txtAddEditRecordDataNsNameServer").prop("disabled", false);
    $("#txtAddEditRecordDataNsNameServer").val("");
    $("#txtAddEditRecordDataNsGlue").prop("disabled", false);
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

    $("#divAddEditRecordDataTxt").hide();
    $("#txtAddEditRecordDataTxt").val("");
    $("#chkAddEditRecordDataTxtSplitText").prop("checked", false);

    $("#divAddEditRecordDataSrv").hide();
    $("#txtAddEditRecordDataSrvPriority").val("");
    $("#txtAddEditRecordDataSrvWeight").val("");
    $("#txtAddEditRecordDataSrvPort").val("");
    $("#txtAddEditRecordDataSrvTarget").val("");

    $("#divAddEditRecordDataNaptr").hide();
    $("#txtAddEditRecordDataNaptrOrder").val("");
    $("#txtAddEditRecordDataNaptrPreference").val("");
    $("#txtAddEditRecordDataNaptrFlags").val("");
    $("#txtAddEditRecordDataNaptrServices").val("");
    $("#txtAddEditRecordDataNaptrRegExp").val("");
    $("#txtAddEditRecordDataNaptrReplacement").val("");

    $("#divAddEditRecordDataDs").hide();
    $("#txtAddEditRecordDataDsKeyTag").val("");
    $("#optAddEditRecordDataDsAlgorithm").val("");
    $("#optAddEditRecordDataDsDigestType").val("");
    $("#txtAddEditRecordDataDsDigest").val("");

    $("#divAddEditRecordDataSshfp").hide();
    $("#optAddEditRecordDataSshfpAlgorithm").val("");
    $("#optAddEditRecordDataSshfpFingerprintType").val("");
    $("#txtAddEditRecordDataSshfpFingerprint").val("");

    $("#divAddEditRecordDataTlsa").hide();
    $("#optAddEditRecordDataTlsaCertificateUsage").val("");
    $("#optAddEditRecordDataTlsaSelector").val("");
    $("#optAddEditRecordDataTlsaMatchingType").val("");
    $("#txtAddEditRecordDataTlsaCertificateAssociationData").val("");

    $("#divAddEditRecordDataSvcb").hide();
    $("#txtAddEditRecordDataSvcbPriority").val("");
    $("#txtAddEditRecordDataSvcbTargetName").val("");
    $("#tableAddEditRecordDataSvcbParams").html("");
    $("#chkAddEditRecordDataSvcbAutoIpv4Hint").prop("checked", false);
    $("#chkAddEditRecordDataSvcbAutoIpv6Hint").prop("checked", false);

    $("#divAddEditRecordDataUri").hide();
    $("#txtAddEditRecordDataUriPriority").val("");
    $("#txtAddEditRecordDataUriWeight").val("");
    $("#txtAddEditRecordDataUri").val("");

    $("#divAddEditRecordDataCaa").hide();
    $("#txtAddEditRecordDataCaaFlags").val("");
    $("#txtAddEditRecordDataCaaTag").val("");
    $("#txtAddEditRecordDataCaaValue").val("");

    $("#divAddEditRecordDataForwarder").hide();
    $("#rdAddEditRecordDataForwarderProtocolUdp").prop("checked", true);
    $("input[name=rdAddEditRecordDataForwarderProtocol]:radio").attr("disabled", false);
    $("#chkAddEditRecordDataForwarderThisServer").prop("checked", false);
    $('#txtAddEditRecordDataForwarder').prop("disabled", false);
    $("#txtAddEditRecordDataForwarder").attr("placeholder", "8.8.8.8 or [2620:fe::10]")
    $("#txtAddEditRecordDataForwarder").val("");
    $("#txtAddEditRecordDataForwarderPriority").val("");
    $("#chkAddEditRecordDataForwarderDnssecValidation").prop("checked", $("#chkDnssecValidation").prop("checked"));
    $("#rdAddEditRecordDataForwarderProxyTypeDefaultProxy").prop("checked", true);
    $("#txtAddEditRecordDataForwarderProxyAddress").prop("disabled", true);
    $("#txtAddEditRecordDataForwarderProxyPort").prop("disabled", true);
    $("#txtAddEditRecordDataForwarderProxyUsername").prop("disabled", true);
    $("#txtAddEditRecordDataForwarderProxyPassword").prop("disabled", true);
    $("#txtAddEditRecordDataForwarderProxyAddress").val("");
    $("#txtAddEditRecordDataForwarderProxyPort").val("");
    $("#txtAddEditRecordDataForwarderProxyUsername").val("");
    $("#txtAddEditRecordDataForwarderProxyPassword").val("");

    $("#divAddEditRecordDataApplication").hide();
    $("#optAddEditRecordDataAppName").html("");
    $("#optAddEditRecordDataAppName").prop("disabled", false);
    $("#optAddEditRecordDataClassPath").html("");
    $("#optAddEditRecordDataClassPath").prop("disabled", false);
    $("#txtAddEditRecordDataData").val("");

    $("#divAddEditRecordOverwrite").show();
    $("#chkAddEditRecordOverwrite").prop("checked", false);

    $("#txtAddEditRecordComments").val("");

    $("#divAddEditRecordExpiryTtl").show();
    $("#txtAddEditRecordExpiryTtl").prop("disabled", false);
    $("#txtAddEditRecordExpiryTtl").val("");

    $("#btnAddEditRecord").button("reset");
}

function showAddRecordModal() {
    var zone = $("#titleEditZone").attr("data-zone");

    var lastType = $("#optAddEditRecordType").val();

    clearAddEditRecordForm();

    if (zone.endsWith(".in-addr.arpa") || zone.endsWith(".ip6.arpa")) {
        $("#optAddEditRecordType").val("PTR");
        modifyAddRecordFormByType(true);
    }
    else if (lastType != "SOA") {
        $("#optAddEditRecordType").val(lastType);
        modifyAddRecordFormByType(true);
    }

    $("#titleAddEditRecord").text("Add Record");
    $("#lblAddEditRecordZoneName").text(zone === "." ? "" : zone);
    $("#optEditRecordTypeSoa").hide();
    $("#btnAddEditRecord").attr("onclick", "addRecord(); return false;");

    $("#modalAddEditRecord").modal("show");

    setTimeout(function () {
        $("#txtAddEditRecordName").trigger("focus");
    }, 1000);
}

var appsList;

function loadAddRecordModalAppNames() {
    var optAddEditRecordDataAppName = $("#optAddEditRecordDataAppName");
    var optAddEditRecordDataClassPath = $("#optAddEditRecordDataClassPath");
    var txtAddEditRecordDataData = $("#txtAddEditRecordDataData");
    var divAddEditRecordAlert = $("#divAddEditRecordAlert");

    optAddEditRecordDataAppName.prop("disabled", true);
    optAddEditRecordDataClassPath.prop("disabled", true);
    txtAddEditRecordDataData.prop("disabled", true);

    optAddEditRecordDataAppName.html("");
    optAddEditRecordDataClassPath.html("");
    txtAddEditRecordDataData.val("");

    var node = $("#optZonesClusterNode").val();

    HTTPRequest({
        url: "api/apps/list?token=" + sessionData.token + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            appsList = responseJSON.response.apps;

            var optApps = "<option></option>";
            var optClassPaths = "<option></option>";

            for (var i = 0; i < appsList.length; i++) {
                for (var j = 0; j < appsList[i].dnsApps.length; j++) {
                    if (appsList[i].dnsApps[j].isAppRecordRequestHandler) {
                        optApps += "<option>" + appsList[i].name + "</option>";
                        break;
                    }
                }
            }

            $("#optAddEditRecordDataAppName").html(optApps);
            $("#optAddEditRecordDataClassPath").html(optClassPaths);

            optAddEditRecordDataAppName.prop("disabled", false);
            optAddEditRecordDataClassPath.prop("disabled", false);
            txtAddEditRecordDataData.prop("disabled", false);
        },
        invalidToken: function () {
            showPageLogin();
        },
        objAlertPlaceholder: divAddEditRecordAlert
    });
}

function modifyAddRecordFormByType(addMode) {
    $("#divAddEditRecordAlert").html("");

    $("#txtAddEditRecordName").prop("placeholder", "@");
    $("#txtAddEditRecordTtl").prop("disabled", false);
    $("#txtAddEditRecordTtl").val("");
    $("#txtAddEditRecordDataValue").attr("placeholder", "");

    var type = $("#optAddEditRecordType").val();

    $("#divAddEditRecordData").hide();
    $("#divAddEditRecordDataUnknownType").hide();
    $("#divAddEditRecordDataPtr").hide();
    $("#divAddEditRecordDataNs").hide();
    $("#divEditRecordDataSoa").hide();
    $("#divAddEditRecordDataMx").hide();
    $("#divAddEditRecordDataTxt").hide();
    $("#divAddEditRecordDataRp").hide();
    $("#divAddEditRecordDataSrv").hide();
    $("#divAddEditRecordDataNaptr").hide();
    $("#divAddEditRecordDataDs").hide();
    $("#divAddEditRecordDataSshfp").hide();
    $("#divAddEditRecordDataTlsa").hide();
    $("#divAddEditRecordDataSvcb").hide();
    $("#divAddEditRecordDataUri").hide();
    $("#divAddEditRecordDataCaa").hide();
    $("#divAddEditRecordDataForwarder").hide();
    $("#divAddEditRecordDataApplication").hide();

    switch (type) {
        case "A":
            $("#lblAddEditRecordDataValue").text("IPv4 Address");
            $("#txtAddEditRecordDataValue").val("");
            $("#chkAddEditRecordDataPtr").prop("checked", false);
            $("#chkAddEditRecordDataCreatePtrZone").prop('disabled', true);
            $("#chkAddEditRecordDataCreatePtrZone").prop("checked", false);
            $("#chkAddEditRecordDataPtrLabel").text("Add reverse (PTR) record");
            $("#divAddEditRecordData").show();
            $("#divAddEditRecordDataPtr").show();
            break;

        case "AAAA":
            $("#lblAddEditRecordDataValue").text("IPv6 Address");
            $("#txtAddEditRecordDataValue").val("");
            $("#chkAddEditRecordDataPtr").prop("checked", false);
            $("#chkAddEditRecordDataCreatePtrZone").prop('disabled', true);
            $("#chkAddEditRecordDataCreatePtrZone").prop("checked", false);
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
            $("#divEditRecordDataSoa").show();
            break;

        case "PTR":
        case "CNAME":
        case "DNAME":
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
            $("#txtAddEditRecordDataTxt").val("");
            $("#chkAddEditRecordDataTxtSplitText").prop("checked", false);
            $("#divAddEditRecordDataTxt").show();
            break;

        case "RP":
            $("#txtAddEditRecordDataRpMailbox").val("");
            $("#txtAddEditRecordDataRpTxtDomain").val("");
            $("#divAddEditRecordDataRp").show();
            break;

        case "SRV":
            $("#txtAddEditRecordName").prop("placeholder", "_service._protocol.name");
            $("#txtAddEditRecordDataSrvPriority").val("");
            $("#txtAddEditRecordDataSrvWeight").val("");
            $("#txtAddEditRecordDataSrvPort").val("");
            $("#txtAddEditRecordDataSrvTarget").val("");
            $("#divAddEditRecordDataSrv").show();
            break;

        case "NAPTR":
            $("#txtAddEditRecordDataNaptrOrder").val("");
            $("#txtAddEditRecordDataNaptrPreference").val("");
            $("#txtAddEditRecordDataNaptrFlags").val("");
            $("#txtAddEditRecordDataNaptrServices").val("");
            $("#txtAddEditRecordDataNaptrRegExp").val("");
            $("#txtAddEditRecordDataNaptrReplacement").val("");
            $("#divAddEditRecordDataNaptr").show();
            break;

        case "DS":
            $("#txtAddEditRecordDataDsKeyTag").val("");
            $("#optAddEditRecordDataDsAlgorithm").val("");
            $("#optAddEditRecordDataDsDigestType").val("");
            $("#txtAddEditRecordDataDsDigest").val("");
            $("#divAddEditRecordDataDs").show();
            break;

        case "SSHFP":
            $("#optAddEditRecordDataSshfpAlgorithm").val("");
            $("#optAddEditRecordDataSshfpFingerprintType").val("");
            $("#txtAddEditRecordDataSshfpFingerprint").val("");
            $("#divAddEditRecordDataSshfp").show();
            break;

        case "TLSA":
            $("#txtAddEditRecordName").prop("placeholder", "_port._protocol.name");
            $("#optAddEditRecordDataTlsaCertificateUsage").val("");
            $("#optAddEditRecordDataTlsaSelector").val("");
            $("#optAddEditRecordDataTlsaMatchingType").val("");
            $("#txtAddEditRecordDataTlsaCertificateAssociationData").val("");
            $("#divAddEditRecordDataTlsa").show();
            break;

        case "SVCB":
        case "HTTPS":
            $("#txtAddEditRecordName").prop("placeholder", "_port._scheme.name");
            $("#txtAddEditRecordDataSvcbPriority").val("");
            $("#txtAddEditRecordDataSvcbTargetName").val("");
            $("#tableAddEditRecordDataSvcbParams").html("");
            $("#chkAddEditRecordDataSvcbAutoIpv4Hint").prop("checked", false);
            $("#chkAddEditRecordDataSvcbAutoIpv6Hint").prop("checked", false);
            $("#divAddEditRecordDataSvcb").show();
            break;

        case "URI":
            $("#txtAddEditRecordDataUriPriority").val("");
            $("#txtAddEditRecordDataUriWeight").val("");
            $("#txtAddEditRecordDataUri").val("");
            $("#divAddEditRecordDataUri").show();
            break;

        case "CAA":
            $("#txtAddEditRecordDataCaaFlags").val("");
            $("#txtAddEditRecordDataCaaTag").val("");
            $("#txtAddEditRecordDataCaaValue").val("");
            $("#divAddEditRecordDataCaa").show();
            break;

        case "FWD":
            $("#txtAddEditRecordTtl").prop("disabled", true);
            $("#txtAddEditRecordTtl").val("0");
            $("input[name=rdAddEditRecordDataForwarderProtocol]:radio").attr("disabled", false);
            $("#rdAddEditRecordDataForwarderProtocolUdp").prop("checked", true);
            $("#chkAddEditRecordDataForwarderThisServer").prop("checked", false);
            $("#txtAddEditRecordDataForwarder").prop("disabled", false);
            $("#txtAddEditRecordDataForwarder").val("");
            $("#txtAddEditRecordDataForwarderPriority").val("");
            $("#chkAddEditRecordDataForwarderDnssecValidation").prop("checked", $("#chkDnssecValidation").prop("checked"));
            $("#rdAddEditRecordDataForwarderProxyTypeDefaultProxy").prop("checked", true);
            $("#txtAddEditRecordDataForwarderProxyAddress").prop("disabled", true);
            $("#txtAddEditRecordDataForwarderProxyPort").prop("disabled", true);
            $("#txtAddEditRecordDataForwarderProxyUsername").prop("disabled", true);
            $("#txtAddEditRecordDataForwarderProxyPassword").prop("disabled", true);
            $("#txtAddEditRecordDataForwarderProxyAddress").val("");
            $("#txtAddEditRecordDataForwarderProxyPort").val("");
            $("#txtAddEditRecordDataForwarderProxyUsername").val("");
            $("#txtAddEditRecordDataForwarderProxyPassword").val("");
            $("#divAddEditRecordDataForwarder").show();
            $("#divAddEditRecordDataForwarderProxy").show();
            break;

        case "APP":
            $("#optAddEditRecordDataAppName").val("");
            $("#optAddEditRecordDataClassPath").val("");
            $("#txtAddEditRecordDataData").val("");
            $("#divAddEditRecordDataApplication").show();

            if (addMode)
                loadAddRecordModalAppNames();

            break;

        default:
            $("#txtAddEditRecordDataUnknownType").val("");
            $("#lblAddEditRecordDataValue").text("RDATA");
            $("#txtAddEditRecordDataValue").val("");
            $("#txtAddEditRecordDataValue").attr("placeholder", "hex string");

            $("#divAddEditRecordData").show();
            $("#divAddEditRecordDataUnknownType").show();
            break;
    }
}

function zoneHasSvcbAutoHint(ipv4, ipv6) {
    if (editZoneRecords == null)
        return true;

    for (var i = 0; i < editZoneRecords.length; i++) {
        switch (editZoneRecords[i].type) {
            case "SVCB":
            case "HTTPS":
                if ((editZoneRecords[i].rData.autoIpv4Hint && ipv4) || (editZoneRecords[i].rData.autoIpv6Hint && ipv6))
                    return true;

                break;
        }
    }

    return false;
}

function addRecord() {
    var btn = $("#btnAddEditRecord");
    var divAddEditRecordAlert = $("#divAddEditRecordAlert");

    var zone = $("#titleEditZone").attr("data-zone");

    var domain;
    {
        var subDomain = $("#txtAddEditRecordName").val();
        if (subDomain === "")
            subDomain = "@";

        if (subDomain === "@")
            domain = zone;
        else if (zone === ".")
            domain = subDomain + ".";
        else
            domain = subDomain + "." + zone;
    }

    var type = $("#optAddEditRecordType").val();

    var ttl = $("#txtAddEditRecordTtl").val();
    var overwrite = $("#chkAddEditRecordOverwrite").prop("checked");
    var comments = $("#txtAddEditRecordComments").val();
    var expiryTtl = $("#txtAddEditRecordExpiryTtl").val();

    var apiUrl = "";

    switch (type) {
        case "A":
        case "AAAA":
            var ipAddress = $("#txtAddEditRecordDataValue").val();
            if (ipAddress === "") {
                showAlert("warning", "Missing!", "Please enter an IP address to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            var updateSvcbHints = zoneHasSvcbAutoHint(type == "A", type == "AAAA");

            apiUrl += "&ipAddress=" + encodeURIComponent(ipAddress) + "&ptr=" + $("#chkAddEditRecordDataPtr").prop('checked') + "&createPtrZone=" + $("#chkAddEditRecordDataCreatePtrZone").prop('checked') + "&updateSvcbHints=" + updateSvcbHints;
            break;

        case "NS":
            var nameServer = $("#txtAddEditRecordDataNsNameServer").val();
            if (nameServer === "") {
                showAlert("warning", "Missing!", "Please enter a name server to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataNsNameServer").trigger("focus");
                return;
            }

            var glue = cleanTextList($("#txtAddEditRecordDataNsGlue").val());

            apiUrl += "&nameServer=" + encodeURIComponent(nameServer) + "&glue=" + encodeURIComponent(glue);
            break;

        case "CNAME":
            var subDomainName = $("#txtAddEditRecordName").val();
            if ((subDomainName === "") || (subDomainName === "@")) {
                showAlert("warning", "Missing!", "Please enter a name for the CNAME record since DNS protocol does not allow CNAME at zone's apex. If you need CNAME like function at the zone's apex then use ANAME record instead.", divAddEditRecordAlert);
                $("#txtAddEditRecordName").trigger("focus");
                return;
            }

            var cname = $("#txtAddEditRecordDataValue").val();
            if (cname === "") {
                showAlert("warning", "Missing!", "Please enter a domain name to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            apiUrl += "&cname=" + encodeURIComponent(cname);
            break;

        case "PTR":
            var ptrName = $("#txtAddEditRecordDataValue").val();
            if (ptrName === "") {
                showAlert("warning", "Missing!", "Please enter a suitable value to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            apiUrl += "&ptrName=" + encodeURIComponent(ptrName);
            break;

        case "MX":
            var preference = $("#txtAddEditRecordDataMxPreference").val();
            if (preference === "")
                preference = 1;

            var exchange = $("#txtAddEditRecordDataMxExchange").val();
            if (exchange === "") {
                showAlert("warning", "Missing!", "Please enter a mail exchange domain name to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataMxExchange").trigger("focus");
                return;
            }

            apiUrl += "&preference=" + preference + "&exchange=" + encodeURIComponent(exchange);
            break;

        case "TXT":
            var text = $("#txtAddEditRecordDataTxt").val();
            if (text === "") {
                showAlert("warning", "Missing!", "Please enter a suitable value to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataTxt").trigger("focus");
                return;
            }

            var splitText = $("#chkAddEditRecordDataTxtSplitText").prop("checked");

            apiUrl += "&text=" + encodeURIComponent(text) + "&splitText=" + splitText;
            break;

        case "RP":
            var mailbox = $("#txtAddEditRecordDataRpMailbox").val();
            if (mailbox === "")
                mailbox = ".";

            var txtDomain = $("#txtAddEditRecordDataRpTxtDomain").val();
            if (txtDomain === "")
                txtDomain = ".";

            apiUrl += "&mailbox=" + encodeURIComponent(mailbox) + "&txtDomain=" + encodeURIComponent(txtDomain);
            break;

        case "SRV":
            if ($("#txtAddEditRecordName").val() === "") {
                showAlert("warning", "Missing!", "Please enter a name that includes service and protocol labels.", divAddEditRecordAlert);
                $("#txtAddEditRecordName").trigger("focus");
                return;
            }

            var priority = $("#txtAddEditRecordDataSrvPriority").val();
            if (priority === "") {
                showAlert("warning", "Missing!", "Please enter a suitable priority.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvPriority").trigger("focus");
                return;
            }

            var weight = $("#txtAddEditRecordDataSrvWeight").val();
            if (weight === "") {
                showAlert("warning", "Missing!", "Please enter a suitable weight.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvWeight").trigger("focus");
                return;
            }

            var port = $("#txtAddEditRecordDataSrvPort").val();
            if (port === "") {
                showAlert("warning", "Missing!", "Please enter a suitable port number.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvPort").trigger("focus");
                return;
            }

            var target = $("#txtAddEditRecordDataSrvTarget").val();
            if (target === "") {
                showAlert("warning", "Missing!", "Please enter a suitable value into the target field.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvTarget").trigger("focus");
                return;
            }

            apiUrl += "&priority=" + priority + "&weight=" + weight + "&port=" + port + "&target=" + encodeURIComponent(target);
            break;

        case "NAPTR":
            var order = $("#txtAddEditRecordDataNaptrOrder").val();
            if (order === "") {
                showAlert("warning", "Missing!", "Please enter a suitable order.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataNaptrOrder").trigger("focus");
                return;
            }

            var preference = $("#txtAddEditRecordDataNaptrPreference").val();
            if (preference === "") {
                showAlert("warning", "Missing!", "Please enter a suitable preference.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataNaptrPreference").trigger("focus");
                return;
            }

            var flags = $("#txtAddEditRecordDataNaptrFlags").val();
            var services = $("#txtAddEditRecordDataNaptrServices").val();
            var regexp = $("#txtAddEditRecordDataNaptrRegExp").val();
            var replacement = $("#txtAddEditRecordDataNaptrReplacement").val();

            apiUrl += "&naptrOrder=" + order + "&naptrPreference=" + preference + "&naptrFlags=" + encodeURIComponent(flags) + "&naptrServices=" + encodeURIComponent(services) + "&naptrRegexp=" + encodeURIComponent(regexp) + "&naptrReplacement=" + encodeURIComponent(replacement);
            break;

        case "DNAME":
            var dname = $("#txtAddEditRecordDataValue").val();
            if (dname === "") {
                showAlert("warning", "Missing!", "Please enter a domain name to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            apiUrl += "&dname=" + encodeURIComponent(dname);
            break;

        case "DS":
            var subDomainName = $("#txtAddEditRecordName").val();
            if ((subDomainName === "") || (subDomainName === "@")) {
                showAlert("warning", "Missing!", "Please enter a name for the DS record.", divAddEditRecordAlert);
                $("#txtAddEditRecordName").trigger("focus");
                return;
            }

            var keyTag = $("#txtAddEditRecordDataDsKeyTag").val();
            if (keyTag === "") {
                showAlert("warning", "Missing!", "Please enter the Key Tag value to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataDsKeyTag").trigger("focus");
                return;
            }

            var algorithm = $("#optAddEditRecordDataDsAlgorithm").val();
            if ((algorithm === null) || (algorithm === "")) {
                showAlert("warning", "Missing!", "Please select an DNSSEC algorithm to add the record.", divAddEditRecordAlert);
                $("#optAddEditRecordDataDsAlgorithm").trigger("focus");
                return;
            }

            var digestType = $("#optAddEditRecordDataDsDigestType").val();
            if ((digestType === null) || (digestType === "")) {
                showAlert("warning", "Missing!", "Please select a Digest Type to add the record.", divAddEditRecordAlert);
                $("#optAddEditRecordDataDsDigestType").trigger("focus");
                return;
            }

            var digest = $("#txtAddEditRecordDataDsDigest").val();
            if (digest === "") {
                showAlert("warning", "Missing!", "Please enter the Digest hash in hex string format to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataDsDigest").trigger("focus");
                return;
            }

            apiUrl += "&keyTag=" + keyTag + "&algorithm=" + algorithm + "&digestType=" + digestType + "&digest=" + encodeURIComponent(digest);
            break;

        case "SSHFP":
            var sshfpAlgorithm = $("#optAddEditRecordDataSshfpAlgorithm").val();
            if ((sshfpAlgorithm === null) || (sshfpAlgorithm === "")) {
                showAlert("warning", "Missing!", "Please select an Algorithm to add the record.", divAddEditRecordAlert);
                $("#optAddEditRecordDataSshfpAlgorithm").trigger("focus");
                return;
            }

            var sshfpFingerprintType = $("#optAddEditRecordDataSshfpFingerprintType").val();
            if ((sshfpFingerprintType === null) || (sshfpFingerprintType === "")) {
                showAlert("warning", "Missing!", "Please select a Fingerprint Type to add the record.", divAddEditRecordAlert);
                $("#optAddEditRecordDataSshfpFingerprintType").trigger("focus");
                return;
            }

            var sshfpFingerprint = $("#txtAddEditRecordDataSshfpFingerprint").val();
            if (sshfpFingerprint === "") {
                showAlert("warning", "Missing!", "Please enter the Fingerprint hash in hex string format to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSshfpFingerprint").trigger("focus");
                return;
            }

            apiUrl += "&sshfpAlgorithm=" + sshfpAlgorithm + "&sshfpFingerprintType=" + sshfpFingerprintType + "&sshfpFingerprint=" + encodeURIComponent(sshfpFingerprint);
            break;

        case "TLSA":
            var tlsaCertificateUsage = $("#optAddEditRecordDataTlsaCertificateUsage").val();
            if ((tlsaCertificateUsage === null) || (tlsaCertificateUsage === "")) {
                showAlert("warning", "Missing!", "Please select a Certificate Usage to add the record.", divAddEditRecordAlert);
                $("#optAddEditRecordDataTlsaCertificateUsage").trigger("focus");
                return;
            }

            var tlsaSelector = $("#optAddEditRecordDataTlsaSelector").val();
            if ((tlsaSelector === null) || (tlsaSelector === "")) {
                showAlert("warning", "Missing!", "Please select a Selector to add the record.", divAddEditRecordAlert);
                $("#optAddEditRecordDataTlsaSelector").trigger("focus");
                return;
            }

            var tlsaMatchingType = $("#optAddEditRecordDataTlsaMatchingType").val();
            if ((tlsaMatchingType === null) || (tlsaMatchingType === "")) {
                showAlert("warning", "Missing!", "Please select a Matching Type to add the record.", divAddEditRecordAlert);
                $("#optAddEditRecordDataTlsaMatchingType").trigger("focus");
                return;
            }

            var tlsaCertificateAssociationData = $("#txtAddEditRecordDataTlsaCertificateAssociationData").val();
            if (tlsaCertificateAssociationData === "") {
                showAlert("warning", "Missing!", "Please enter the Certificate Association Data to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataTlsaCertificateAssociationData").trigger("focus");
                return;
            }

            if ((tlsaMatchingType === "Full") && !tlsaCertificateAssociationData.startsWith("-")) {
                showAlert("warning", "Missing!", "Please enter a complete certificate in PEM format as the Certificate Association Data to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataTlsaCertificateAssociationData").trigger("focus");
                return;
            }

            apiUrl += "&tlsaCertificateUsage=" + tlsaCertificateUsage + "&tlsaSelector=" + tlsaSelector + "&tlsaMatchingType=" + tlsaMatchingType + "&tlsaCertificateAssociationData=" + encodeURIComponent(tlsaCertificateAssociationData);
            break;

        case "SVCB":
        case "HTTPS":
            var svcPriority = $("#txtAddEditRecordDataSvcbPriority").val();
            if ((svcPriority === null) || (svcPriority === "")) {
                showAlert("warning", "Missing!", "Please enter a Priority value to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSvcbPriority").trigger("focus");
                return;
            }

            var svcTargetName = $("#txtAddEditRecordDataSvcbTargetName").val();
            if ((svcTargetName === null) || (svcTargetName === "")) {
                showAlert("warning", "Missing!", "Please enter a Target Name to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSvcbTargetName").trigger("focus");
                return;
            }

            var svcParams = serializeTableData($("#tableAddEditRecordDataSvcbParams"), 2, divAddEditRecordAlert);
            if (svcParams === false)
                return;

            if (svcParams.length === 0)
                svcParams = false;

            var autoIpv4Hint = $("#chkAddEditRecordDataSvcbAutoIpv4Hint").prop("checked");
            var autoIpv6Hint = $("#chkAddEditRecordDataSvcbAutoIpv6Hint").prop("checked");

            apiUrl += "&svcPriority=" + svcPriority + "&svcTargetName=" + encodeURIComponent(svcTargetName) + "&svcParams=" + encodeURIComponent(svcParams) + "&autoIpv4Hint=" + autoIpv4Hint + "&autoIpv6Hint=" + autoIpv6Hint;
            break;

        case "URI":
            var uriPriority = $("#txtAddEditRecordDataUriPriority").val();
            if (uriPriority === "") {
                showAlert("warning", "Missing!", "Please enter a suitable priority.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataUriPriority").trigger("focus");
                return;
            }

            var uriWeight = $("#txtAddEditRecordDataUriWeight").val();
            if (uriWeight === "") {
                showAlert("warning", "Missing!", "Please enter a suitable weight.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataUriWeight").trigger("focus");
                return;
            }

            var uri = $("#txtAddEditRecordDataUri").val();
            if (uri === "") {
                showAlert("warning", "Missing!", "Please enter a suitable value into the URI field.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataUri").trigger("focus");
                return;
            }

            apiUrl += "&uriPriority=" + uriPriority + "&uriWeight=" + uriWeight + "&uri=" + encodeURIComponent(uri);
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
                $("#txtAddEditRecordDataCaaValue").trigger("focus");
                return;
            }

            apiUrl += "&flags=" + flags + "&tag=" + encodeURIComponent(tag) + "&value=" + encodeURIComponent(value);
            break;

        case "ANAME":
            var aname = $("#txtAddEditRecordDataValue").val();
            if (aname === "") {
                showAlert("warning", "Missing!", "Please enter a suitable value to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            apiUrl += "&aname=" + encodeURIComponent(aname);
            break;

        case "FWD":
            var forwarder = $("#txtAddEditRecordDataForwarder").val();
            if (forwarder === "") {
                showAlert("warning", "Missing!", "Please enter a domain name or IP address or URL as a forwarder to add the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataForwarder").trigger("focus");
                return;
            }

            var forwarderPriority = $("#txtAddEditRecordDataForwarderPriority").val();
            var dnssecValidation = $("#chkAddEditRecordDataForwarderDnssecValidation").prop("checked");
            var proxyType = $("input[name=rdAddEditRecordDataForwarderProxyType]:checked").val();

            apiUrl += "&protocol=" + $('input[name=rdAddEditRecordDataForwarderProtocol]:checked').val() + "&forwarder=" + encodeURIComponent(forwarder);
            apiUrl += "&forwarderPriority=" + forwarderPriority + "&dnssecValidation=" + dnssecValidation + "&proxyType=" + proxyType;

            switch (proxyType) {
                case "Http":
                case "Socks5":
                    var proxyAddress = $("#txtAddEditRecordDataForwarderProxyAddress").val();
                    var proxyPort = $("#txtAddEditRecordDataForwarderProxyPort").val();
                    var proxyUsername = $("#txtAddEditRecordDataForwarderProxyUsername").val();
                    var proxyPassword = $("#txtAddEditRecordDataForwarderProxyPassword").val();

                    if ((proxyAddress == null) || (proxyAddress === "")) {
                        showAlert("warning", "Missing!", "Please enter a domain name or IP address for Proxy Server Address to add the record.", divAddEditRecordAlert);
                        $("#txtAddEditRecordDataForwarderProxyAddress").trigger("focus");
                        return;
                    }

                    if ((proxyPort == null) || (proxyPort === "")) {
                        showAlert("warning", "Missing!", "Please enter a port number for Proxy Server Port to add the record.", divAddEditRecordAlert);
                        $("#txtAddEditRecordDataForwarderProxyPort").trigger("focus");
                        return;
                    }

                    apiUrl += "&proxyAddress=" + encodeURIComponent(proxyAddress) + "&proxyPort=" + proxyPort + "&proxyUsername=" + encodeURIComponent(proxyUsername) + "&proxyPassword=" + encodeURIComponent(proxyPassword);
                    break;
            }
            break;

        case "APP":
            var appName = $("#optAddEditRecordDataAppName").val();

            if ((appName === null) || (appName === "")) {
                showAlert("warning", "Missing!", "Please select an application name to add record.", divAddEditRecordAlert);
                $("#optAddEditRecordDataAppName").trigger("focus");
                return;
            }

            var classPath = $("#optAddEditRecordDataClassPath").val();

            if ((classPath === null) || (classPath === "")) {
                showAlert("warning", "Missing!", "Please select a class path to add record.", divAddEditRecordAlert);
                $("#optAddEditRecordDataClassPath").trigger("focus");
                return;
            }

            var recordData = $("#txtAddEditRecordDataData").val();

            apiUrl += "&appName=" + encodeURIComponent(appName) + "&classPath=" + encodeURIComponent(classPath) + "&recordData=" + encodeURIComponent(recordData);
            break;

        default:
            type = $("#txtAddEditRecordDataUnknownType").val();
            if ((type === null) || (type === "")) {
                showAlert("warning", "Missing!", "Please enter a resoure record name or number to add record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataUnknownType").trigger("focus");
                return;
            }

            var rdata = $("#txtAddEditRecordDataValue").val();
            if ((rdata === null) || (rdata === "")) {
                showAlert("warning", "Missing!", "Please enter a hex value as the RDATA to add record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            apiUrl += "&rdata=" + encodeURIComponent(rdata);
            break;
    }

    var node = $("#optZonesClusterNode").val();

    apiUrl = "api/zones/records/add?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&domain=" + encodeURIComponent(domain) + "&type=" + encodeURIComponent(type) + "&ttl=" + ttl + "&overwrite=" + overwrite + "&comments=" + encodeURIComponent(comments) + "&expiryTtl=" + expiryTtl + apiUrl;

    btn.button("loading");

    HTTPRequest({
        url: apiUrl + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            $("#modalAddEditRecord").modal("hide");

            if (overwrite) {
                var currentPageNumber = Number($("#txtEditZonePageNumber").val());
                showEditZone(zone, currentPageNumber);
            }
            else {
                //update local array
                editZoneRecords.unshift(responseJSON.response.addedRecord);
                editZoneFilteredRecords = null; //to evaluate filters again

                //show page
                showEditZonePage(1);
            }

            showAlert("success", "Record Added!", "Resource record was added successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalAddEditRecord").modal("hide");
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
        case "Quic":
            $("#txtAddEditRecordDataForwarder").attr("placeholder", "dns.quad9.net (9.9.9.9:853)")
            break;

        case "Https":
            $("#txtAddEditRecordDataForwarder").attr("placeholder", "https://cloudflare-dns.com/dns-query (1.1.1.1)")
            break;
    }
}

function updateAddEditFormForwarderProxyType() {
    var proxyType = $('input[name=rdAddEditRecordDataForwarderProxyType]:checked').val();
    var disabled = (proxyType === "NoProxy") || (proxyType === "DefaultProxy");

    $("#txtAddEditRecordDataForwarderProxyAddress").prop("disabled", disabled);
    $("#txtAddEditRecordDataForwarderProxyPort").prop("disabled", disabled);
    $("#txtAddEditRecordDataForwarderProxyUsername").prop("disabled", disabled);
    $("#txtAddEditRecordDataForwarderProxyPassword").prop("disabled", disabled);
}

function updateAddEditFormForwarderThisServer() {
    var useThisServer = $("#chkAddEditRecordDataForwarderThisServer").prop('checked');

    if (useThisServer) {
        $("input[name=rdAddEditRecordDataForwarderProtocol]:radio").attr("disabled", true);
        $("#rdAddEditRecordDataForwarderProtocolUdp").prop("checked", true);
        $("#txtAddEditRecordDataForwarder").attr("placeholder", "8.8.8.8 or [2620:fe::10]")

        $("#txtAddEditRecordDataForwarder").prop("disabled", true);
        $("#txtAddEditRecordDataForwarder").val("this-server");

        $("#divAddEditRecordDataForwarderProxy").hide();
    }
    else {
        $("input[name=rdAddEditRecordDataForwarderProtocol]:radio").attr("disabled", false);

        $("#txtAddEditRecordDataForwarder").prop("disabled", false);
        $("#txtAddEditRecordDataForwarder").val("");

        $("#divAddEditRecordDataForwarderProxy").show();
    }
}

function addSvcbRecordParamEditRow(paramKey, paramValue) {
    var id = Math.floor(Math.random() * 10000);

    var tableHtmlRows = "<tr id=\"tableAddEditRecordDataSvcbParamsRow" + id + "\">";

    if ((paramKey != "") && isFinite(paramKey)) {
        tableHtmlRows += "<td><input type=\"text\" class=\"form-control\" placeholder=\"key number\" value=\"" + htmlEncode(paramKey) + "\"></td>";
        tableHtmlRows += "<td><input type=\"text\" data-optional=\"true\" class=\"form-control\" placeholder=\"hex string\" value=\"" + htmlEncode(paramValue) + "\"></td>";
    }
    else {
        tableHtmlRows += "<td id=\"tableAddEditRecordDataSvcbParamsRowColumn1" + id + "\">";
        tableHtmlRows += "<select class=\"form-control\" onchange=\"if (event.target.value === 'Unknown') { $('#tableAddEditRecordDataSvcbParamsRowColumn1" + id + "').html('<input type=\\\'text\\\' class=\\\'form-control\\\' placeholder=\\\'key number\\\' >'); $('#tableAddEditRecordDataSvcbParamsRowColumn2" + id + "').html('<input type=\\\'text\\\' data-optional=\\\'true\\\' class=\\\'form-control\\\' placeholder=\\\'hex string\\\' >'); }\">";
        tableHtmlRows += "<option" + (paramKey == "mandatory" ? " selected" : "") + ">mandatory</option>";
        tableHtmlRows += "<option" + (paramKey == "alpn" ? " selected" : "") + ">alpn</option>";
        tableHtmlRows += "<option" + (paramKey == "no-default-alpn" ? " selected" : "") + ">no-default-alpn</option>";
        tableHtmlRows += "<option" + (paramKey == "port" ? " selected" : "") + ">port</option>";
        tableHtmlRows += "<option" + (paramKey == "ipv4hint" ? " selected" : "") + ">ipv4hint</option>";
        tableHtmlRows += "<option" + (paramKey == "ipv6hint" ? " selected" : "") + ">ipv6hint</option>";
        tableHtmlRows += "<option" + (paramKey == "dohpath" ? " selected" : "") + ">dohpath</option>";
        tableHtmlRows += "<option>Unknown</option>";
        tableHtmlRows += "</select></td>";

        tableHtmlRows += "<td id=\"tableAddEditRecordDataSvcbParamsRowColumn2" + id + "\"><input type=\"text\" data-optional=\"true\" class=\"form-control\" value=\"" + htmlEncode(paramValue) + "\"></td>";
    }

    tableHtmlRows += "<td><button type=\"button\" class=\"btn btn-warning\" onclick=\"$('#tableAddEditRecordDataSvcbParamsRow" + id + "').remove();\">Remove</button></td></tr>";

    $("#tableAddEditRecordDataSvcbParams").append(tableHtmlRows);
}

function showEditRecordModal(objBtn) {
    var btn = $(objBtn);
    var id = btn.attr("data-id");
    var divData = $("#data" + id);

    var zone = $("#titleEditZone").attr("data-zone");
    var zoneType = $("#titleEditZone").attr("data-zone-type");
    var catalogZone = $("#titleEditZoneCatalog").text();
    var name = divData.attr("data-record-name");
    var type = divData.attr("data-record-type");
    var ttl = divData.attr("data-record-ttl");
    var comments = divData.attr("data-record-comments");
    var expiryTtl = divData.attr("data-record-expiry-ttl");

    if (name === zone)
        name = "@";
    else
        name = name.replace("." + zone, "");

    clearAddEditRecordForm();
    $("#titleAddEditRecord").text("Edit Record");
    $("#lblAddEditRecordZoneName").text(zone === "." ? "" : zone);
    $("#optEditRecordTypeSoa").show();
    $("#optAddEditRecordType").val(type);
    $("#divAddEditRecordOverwrite").hide();
    modifyAddRecordFormByType(false);

    $("#txtAddEditRecordName").val(name);
    $("#txtAddEditRecordTtl").val(ttl)
    $("#txtAddEditRecordComments").val(comments);
    $("#txtAddEditRecordExpiryTtl").val(expiryTtl);

    switch (type) {
        case "A":
        case "AAAA":
            $("#txtAddEditRecordDataValue").val(divData.attr("data-record-ip-address"));
            $("#chkAddEditRecordDataPtr").prop("checked", false);
            $("#chkAddEditRecordDataCreatePtrZone").prop("disabled", true);
            $("#chkAddEditRecordDataCreatePtrZone").prop("checked", false);
            $("#chkAddEditRecordDataPtrLabel").text("Update reverse (PTR) record");
            break;

        case "NS":
            if ((zoneType == "Primary") && (name == "@") && sessionData.info.clusterInitialized && (catalogZone == "cluster-catalog." + sessionData.info.clusterDomain)) {
                $("#txtAddEditRecordName").prop("disabled", true);
                $("#txtAddEditRecordDataNsNameServer").prop("disabled", true);
                $("#txtAddEditRecordDataNsGlue").prop("disabled", true);
                $("#txtAddEditRecordExpiryTtl").prop("disabled", true);
            }

            $("#txtAddEditRecordDataNsNameServer").val(divData.attr("data-record-name-server"));
            $("#txtAddEditRecordDataNsGlue").val(divData.attr("data-record-glue").replace(/, /g, "\n"));
            break;

        case "CNAME":
            $("#txtAddEditRecordDataValue").val(divData.attr("data-record-cname"));
            break;

        case "SOA":
            $("#txtEditRecordDataSoaPrimaryNameServer").val(divData.attr("data-record-pname"));
            $("#txtEditRecordDataSoaResponsiblePerson").val(divData.attr("data-record-rperson"));
            $("#txtEditRecordDataSoaSerial").val(divData.attr("data-record-serial"));
            $("#txtEditRecordDataSoaSerial").prop("disabled", divData.attr("data-record-serial-scheme") === "true");
            $("#txtEditRecordDataSoaRefresh").val(divData.attr("data-record-refresh"));
            $("#txtEditRecordDataSoaRetry").val(divData.attr("data-record-retry"));
            $("#txtEditRecordDataSoaExpire").val(divData.attr("data-record-expire"));
            $("#txtEditRecordDataSoaMinimum").val(divData.attr("data-record-minimum"));
            $("#chkEditRecordDataSoaUseSerialDateScheme").prop("checked", divData.attr("data-record-serial-scheme") === "true");

            $("#txtAddEditRecordName").prop("disabled", true);
            $("#divAddEditRecordExpiryTtl").hide();

            switch (zoneType) {
                case "Primary":
                    if (sessionData.info.clusterInitialized && (catalogZone == "cluster-catalog." + sessionData.info.clusterDomain))
                        $("#txtEditRecordDataSoaPrimaryNameServer").prop("disabled", true);
                    else
                        $("#txtEditRecordDataSoaPrimaryNameServer").prop("disabled", false);

                    $("#txtAddEditRecordTtl").prop("disabled", false);
                    $("#txtEditRecordDataSoaResponsiblePerson").prop("disabled", false);
                    break;

                case "Forwarder":
                    $("#txtAddEditRecordTtl").prop("disabled", true);
                    $("#txtEditRecordDataSoaResponsiblePerson").prop("disabled", true);
                    break;

                case "Catalog":
                    $("#txtAddEditRecordTtl").prop("disabled", true);
                    $("#txtEditRecordDataSoaPrimaryNameServer").prop("disabled", true);
                    $("#txtEditRecordDataSoaResponsiblePerson").prop("disabled", true);
                    break;

                default:
                    $("#txtAddEditRecordTtl").prop("disabled", false);
                    $("#txtEditRecordDataSoaPrimaryNameServer").prop("disabled", false);
                    $("#txtEditRecordDataSoaResponsiblePerson").prop("disabled", false);
                    break;
            }

            break;

        case "PTR":
            $("#txtAddEditRecordDataValue").val(divData.attr("data-record-ptr-name"));
            break;

        case "MX":
            $("#txtAddEditRecordDataMxPreference").val(divData.attr("data-record-preference"));
            $("#txtAddEditRecordDataMxExchange").val(divData.attr("data-record-exchange"));
            break;

        case "TXT":
            $("#txtAddEditRecordDataTxt").val(divData.attr("data-record-text"));
            $("#chkAddEditRecordDataTxtSplitText").prop("checked", divData.attr("data-record-split-text") === "true");
            break;

        case "RP":
            $("#txtAddEditRecordDataRpMailbox").val(divData.attr("data-record-mailbox"));
            $("#txtAddEditRecordDataRpTxtDomain").val(divData.attr("data-record-txt-domain"));
            break;

        case "SRV":
            $("#txtAddEditRecordDataSrvPriority").val(divData.attr("data-record-priority"));
            $("#txtAddEditRecordDataSrvWeight").val(divData.attr("data-record-weight"));
            $("#txtAddEditRecordDataSrvPort").val(divData.attr("data-record-port"));
            $("#txtAddEditRecordDataSrvTarget").val(divData.attr("data-record-target"));
            break;

        case "NAPTR":
            $("#txtAddEditRecordDataNaptrOrder").val(divData.attr("data-record-order"));
            $("#txtAddEditRecordDataNaptrPreference").val(divData.attr("data-record-preference"));
            $("#txtAddEditRecordDataNaptrFlags").val(divData.attr("data-record-flags"));
            $("#txtAddEditRecordDataNaptrServices").val(divData.attr("data-record-services"));
            $("#txtAddEditRecordDataNaptrRegExp").val(divData.attr("data-record-regexp"));
            $("#txtAddEditRecordDataNaptrReplacement").val(divData.attr("data-record-replacement"));
            break;

        case "DNAME":
            $("#txtAddEditRecordDataValue").val(divData.attr("data-record-dname"));
            break;

        case "DS":
            $("#txtAddEditRecordDataDsKeyTag").val(divData.attr("data-record-key-tag"));
            $("#optAddEditRecordDataDsAlgorithm").val(divData.attr("data-record-algorithm"));
            $("#optAddEditRecordDataDsDigestType").val(divData.attr("data-record-digest-type"));
            $("#txtAddEditRecordDataDsDigest").val(divData.attr("data-record-digest"));
            break;

        case "SSHFP":
            $("#optAddEditRecordDataSshfpAlgorithm").val(divData.attr("data-record-algorithm"));
            $("#optAddEditRecordDataSshfpFingerprintType").val(divData.attr("data-record-fingerprint-type"));
            $("#txtAddEditRecordDataSshfpFingerprint").val(divData.attr("data-record-fingerprint"));
            break;

        case "TLSA":
            $("#optAddEditRecordDataTlsaCertificateUsage").val(divData.attr("data-record-certificate-usage"));
            $("#optAddEditRecordDataTlsaSelector").val(divData.attr("data-record-selector"));
            $("#optAddEditRecordDataTlsaMatchingType").val(divData.attr("data-record-matching-type"));
            $("#txtAddEditRecordDataTlsaCertificateAssociationData").val(divData.attr("data-record-certificate-association-data"));
            break;

        case "SVCB":
        case "HTTPS":
            $("#txtAddEditRecordDataSvcbPriority").val(divData.attr("data-record-svc-priority"));
            $("#txtAddEditRecordDataSvcbTargetName").val(divData.attr("data-record-svc-target-name"));

            var svcParams = JSON.parse(divData.attr("data-record-svc-params"));
            var autoIpv4Hint = divData.attr("data-record-auto-ipv4hint") === "true";
            var autoIpv6Hint = divData.attr("data-record-auto-ipv6hint") === "true";

            for (var paramKey in svcParams) {
                switch (paramKey) {
                    case "ipv4hint":
                        if (autoIpv4Hint)
                            continue;

                        break;

                    case "ipv6hint":
                        if (autoIpv6Hint)
                            continue;

                        break;
                }

                addSvcbRecordParamEditRow(paramKey, svcParams[paramKey]);
            }

            $("#chkAddEditRecordDataSvcbAutoIpv4Hint").prop("checked", autoIpv4Hint);
            $("#chkAddEditRecordDataSvcbAutoIpv6Hint").prop("checked", autoIpv6Hint);
            break;

        case "URI":
            $("#txtAddEditRecordDataUriPriority").val(divData.attr("data-record-priority"));
            $("#txtAddEditRecordDataUriWeight").val(divData.attr("data-record-weight"));
            $("#txtAddEditRecordDataUri").val(divData.attr("data-record-uri"));
            break;

        case "CAA":
            $("#txtAddEditRecordDataCaaFlags").val(divData.attr("data-record-flags"));
            $("#txtAddEditRecordDataCaaTag").val(divData.attr("data-record-tag"));
            $("#txtAddEditRecordDataCaaValue").val(divData.attr("data-record-value"));
            break;

        case "ANAME":
            $("#txtAddEditRecordDataValue").val(divData.attr("data-record-aname"));
            break;

        case "FWD":
            $("#txtAddEditRecordTtl").prop("disabled", true);
            $("#rdAddEditRecordDataForwarderProtocol" + divData.attr("data-record-protocol")).prop("checked", true);

            var forwarder = divData.attr("data-record-forwarder");

            $("#chkAddEditRecordDataForwarderThisServer").prop("checked", (forwarder == "this-server"));
            $("#txtAddEditRecordDataForwarder").prop("disabled", (forwarder == "this-server"));
            $("#txtAddEditRecordDataForwarder").val(forwarder);

            if (forwarder === "this-server") {
                $("input[name=rdAddEditRecordDataForwarderProtocol]:radio").attr("disabled", true);
                $("#divAddEditRecordDataForwarderProxy").hide();
            }
            else {
                $("input[name=rdAddEditRecordDataForwarderProtocol]:radio").attr("disabled", false);
                $("#divAddEditRecordDataForwarderProxy").show();
            }

            $("#txtAddEditRecordDataForwarderPriority").val(divData.attr("data-record-priority"));
            $("#chkAddEditRecordDataForwarderDnssecValidation").prop("checked", divData.attr("data-record-dnssec-validation") === "true");

            var proxyType = divData.attr("data-record-proxy-type");
            $("#rdAddEditRecordDataForwarderProxyType" + proxyType).prop("checked", true);

            switch (proxyType) {
                case "Http":
                case "Socks5":
                    $("#txtAddEditRecordDataForwarderProxyAddress").val(divData.attr("data-record-proxy-address"));
                    $("#txtAddEditRecordDataForwarderProxyPort").val(divData.attr("data-record-proxy-port"));
                    $("#txtAddEditRecordDataForwarderProxyUsername").val(divData.attr("data-record-proxy-username"));
                    $("#txtAddEditRecordDataForwarderProxyPassword").val(divData.attr("data-record-proxy-password"));
                    break;
            }

            updateAddEditFormForwarderPlaceholder();
            updateAddEditFormForwarderProxyType();
            break;

        case "APP":
            $("#optAddEditRecordDataAppName").prop("disabled", true);
            $("#optAddEditRecordDataClassPath").prop("disabled", true);

            $("#optAddEditRecordDataAppName").html("<option>" + divData.attr("data-record-app-name") + "</option>")
            $("#optAddEditRecordDataAppName").val(divData.attr("data-record-app-name"))

            $("#optAddEditRecordDataClassPath").html("<option>" + divData.attr("data-record-classpath") + "</option>")
            $("#optAddEditRecordDataClassPath").val(divData.attr("data-record-classpath"))

            $("#txtAddEditRecordDataData").val(divData.attr("data-record-data"))
            break;

        default:
            var rdata = divData.attr("data-record-rdata");

            if (rdata == null) {
                showAlert("danger", "Not Supported!", "Editing this record type is not supported.");
                return;
            }

            $("#optAddEditRecordType").val("Unknown");
            $("#txtAddEditRecordDataUnknownType").val(type);
            $("#txtAddEditRecordDataUnknownType").prop("disabled", true);

            $("#txtAddEditRecordDataValue").val(rdata);
            break;
    }

    $("#optAddEditRecordType").prop("disabled", true);

    $("#btnAddEditRecord").attr("data-id", id);
    $("#btnAddEditRecord").attr("onclick", "updateRecord(); return false;");

    $("#modalAddEditRecord").modal("show");

    setTimeout(function () {
        $("#txtAddEditRecordName").trigger("focus");
    }, 1000);
}

function updateRecord() {
    var btn = $("#btnAddEditRecord");
    var divAddEditRecordAlert = $("#divAddEditRecordAlert");

    var index = Number(btn.attr("data-id"));
    var divData = $("#data" + index);

    var zone = $("#titleEditZone").attr("data-zone");
    var recordIndex = Number(divData.attr("data-record-index"));
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
    var disable = (divData.attr("data-record-disabled") === "true");
    var comments = $("#txtAddEditRecordComments").val();
    var expiryTtl = $("#txtAddEditRecordExpiryTtl").val();

    var apiUrl = "";

    switch (type) {
        case "A":
        case "AAAA":
            var ipAddress = divData.attr("data-record-ip-address");

            var newIpAddress = $("#txtAddEditRecordDataValue").val();
            if (newIpAddress === "") {
                showAlert("warning", "Missing!", "Please enter an IP address to update the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            var updateSvcbHints = zoneHasSvcbAutoHint(type == "A", type == "AAAA");

            apiUrl += "&ipAddress=" + encodeURIComponent(ipAddress) + "&newIpAddress=" + encodeURIComponent(newIpAddress) + "&ptr=" + $("#chkAddEditRecordDataPtr").prop('checked') + "&createPtrZone=" + $("#chkAddEditRecordDataCreatePtrZone").prop('checked') + "&updateSvcbHints=" + updateSvcbHints;
            break;

        case "NS":
            var nameServer = divData.attr("data-record-name-server");

            var newNameServer = $("#txtAddEditRecordDataNsNameServer").val();
            if (newNameServer === "") {
                showAlert("warning", "Missing!", "Please enter a name server to update the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataNsNameServer").trigger("focus");
                return;
            }

            var glue = cleanTextList($("#txtAddEditRecordDataNsGlue").val());

            apiUrl += "&nameServer=" + encodeURIComponent(nameServer) + "&newNameServer=" + encodeURIComponent(newNameServer) + "&glue=" + encodeURIComponent(glue);
            break;

        case "CNAME":
            var subDomainName = $("#txtAddEditRecordName").val();
            if ((subDomainName === "") || (subDomainName === "@")) {
                showAlert("warning", "Missing!", "Please enter a name for the CNAME record since DNS protocol does not allow CNAME at zone's apex. If you need CNAME like function at the zone's apex then use ANAME record instead.", divAddEditRecordAlert);
                $("#txtAddEditRecordName").trigger("focus");
                return;
            }

            var cname = $("#txtAddEditRecordDataValue").val();
            if (cname === "") {
                showAlert("warning", "Missing!", "Please enter a domain name to update the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            apiUrl += "&cname=" + encodeURIComponent(cname);
            break;

        case "SOA":
            var primaryNameServer = $("#txtEditRecordDataSoaPrimaryNameServer").val();
            if (primaryNameServer === "") {
                showAlert("warning", "Missing!", "Please enter a value for primary name server.", divAddEditRecordAlert);
                $("#txtEditRecordDataSoaPrimaryNameServer").trigger("focus");
                return;
            }

            var responsiblePerson = $("#txtEditRecordDataSoaResponsiblePerson").val();
            if (responsiblePerson === "") {
                showAlert("warning", "Missing!", "Please enter a value for responsible person.", divAddEditRecordAlert);
                $("#txtEditRecordDataSoaResponsiblePerson").trigger("focus");
                return;
            }

            var serial = $("#txtEditRecordDataSoaSerial").val();
            if (serial === "") {
                showAlert("warning", "Missing!", "Please enter a value for serial.", divAddEditRecordAlert);
                $("#txtEditRecordDataSoaSerial").trigger("focus");
                return;
            }

            var refresh = $("#txtEditRecordDataSoaRefresh").val();
            if (refresh === "") {
                showAlert("warning", "Missing!", "Please enter a value for refresh.", divAddEditRecordAlert);
                $("#txtEditRecordDataSoaRefresh").trigger("focus");
                return;
            }

            var retry = $("#txtEditRecordDataSoaRetry").val();
            if (retry === "") {
                showAlert("warning", "Missing!", "Please enter a value for retry.", divAddEditRecordAlert);
                $("#txtEditRecordDataSoaRetry").trigger("focus");
                return;
            }

            var expire = $("#txtEditRecordDataSoaExpire").val();
            if (expire === "") {
                showAlert("warning", "Missing!", "Please enter a value for expire.", divAddEditRecordAlert);
                $("#txtEditRecordDataSoaExpire").trigger("focus");
                return;
            }

            var minimum = $("#txtEditRecordDataSoaMinimum").val();
            if (minimum === "") {
                showAlert("warning", "Missing!", "Please enter a value for minimum.", divAddEditRecordAlert);
                $("#txtEditRecordDataSoaMinimum").trigger("focus");
                return;
            }

            var useSerialDateScheme = $("#chkEditRecordDataSoaUseSerialDateScheme").prop("checked");

            apiUrl += "&primaryNameServer=" + encodeURIComponent(primaryNameServer) +
                "&responsiblePerson=" + encodeURIComponent(responsiblePerson) +
                "&serial=" + encodeURIComponent(serial) +
                "&refresh=" + encodeURIComponent(refresh) +
                "&retry=" + encodeURIComponent(retry) +
                "&expire=" + encodeURIComponent(expire) +
                "&minimum=" + encodeURIComponent(minimum) +
                "&useSerialDateScheme=" + encodeURIComponent(useSerialDateScheme);

            break;

        case "PTR":
            var ptrName = divData.attr("data-record-ptr-name");

            var newPtrName = $("#txtAddEditRecordDataValue").val();
            if (newPtrName === "") {
                showAlert("warning", "Missing!", "Please enter a suitable value to update the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            apiUrl += "&ptrName=" + encodeURIComponent(ptrName) + "&newPtrName=" + encodeURIComponent(newPtrName);
            break;

        case "MX":
            var preference = divData.attr("data-record-preference");

            var newPreference = $("#txtAddEditRecordDataMxPreference").val();
            if (newPreference === "")
                newPreference = 1;

            var exchange = divData.attr("data-record-exchange");

            var newExchange = $("#txtAddEditRecordDataMxExchange").val();
            if (newExchange === "") {
                showAlert("warning", "Missing!", "Please enter a mail exchange domain name to update the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataMxExchange").trigger("focus");
                return;
            }

            apiUrl += "&preference=" + preference + "&newPreference=" + newPreference + "&exchange=" + encodeURIComponent(exchange) + "&newExchange=" + encodeURIComponent(newExchange);
            break;

        case "TXT":
            var text = divData.attr("data-record-text");

            var newText = $("#txtAddEditRecordDataTxt").val();
            if (newText === "") {
                showAlert("warning", "Missing!", "Please enter a suitable value to update the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataTxt").trigger("focus");
                return;
            }

            var splitText = divData.attr("data-record-split-text");
            var newSplitText = $("#chkAddEditRecordDataTxtSplitText").prop("checked");

            apiUrl += "&text=" + encodeURIComponent(text) + "&newText=" + encodeURIComponent(newText) + "&splitText=" + splitText + "&newSplitText=" + newSplitText;
            break;

        case "RP":
            var mailbox = divData.attr("data-record-mailbox");

            var newMailbox = $("#txtAddEditRecordDataRpMailbox").val();
            if (newMailbox === "")
                newMailbox = ".";

            var txtDomain = divData.attr("data-record-txt-domain");

            var newTxtDomain = $("#txtAddEditRecordDataRpTxtDomain").val();
            if (newTxtDomain === "")
                newTxtDomain = ".";

            apiUrl += "&mailbox=" + encodeURIComponent(mailbox) + "&newMailbox=" + encodeURIComponent(newMailbox) + "&txtDomain=" + encodeURIComponent(txtDomain) + "&newTxtDomain=" + encodeURIComponent(newTxtDomain);
            break;

        case "SRV":
            if ($("#txtAddEditRecordName").val() === "") {
                showAlert("warning", "Missing!", "Please enter a name that includes service and protocol labels.", divAddEditRecordAlert);
                $("#txtAddEditRecordName").trigger("focus");
                return;
            }

            var priority = divData.attr("data-record-priority");

            var newPriority = $("#txtAddEditRecordDataSrvPriority").val();
            if (newPriority === "") {
                showAlert("warning", "Missing!", "Please enter a suitable priority.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvPriority").trigger("focus");
                return;
            }

            var weight = divData.attr("data-record-weight");

            var newWeight = $("#txtAddEditRecordDataSrvWeight").val();
            if (newWeight === "") {
                showAlert("warning", "Missing!", "Please enter a suitable weight.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvWeight").trigger("focus");
                return;
            }

            var port = divData.attr("data-record-port");

            var newPort = $("#txtAddEditRecordDataSrvPort").val();
            if (newPort === "") {
                showAlert("warning", "Missing!", "Please enter a suitable port number.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvPort").trigger("focus");
                return;
            }

            var target = divData.attr("data-record-target");

            var newTarget = $("#txtAddEditRecordDataSrvTarget").val();
            if (newTarget === "") {
                showAlert("warning", "Missing!", "Please enter a suitable value into the target field.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSrvTarget").trigger("focus");
                return;
            }

            apiUrl += "&priority=" + priority + "&newPriority=" + newPriority + "&weight=" + weight + "&newWeight=" + newWeight + "&port=" + port + "&newPort=" + newPort + "&target=" + encodeURIComponent(target) + "&newTarget=" + encodeURIComponent(newTarget);
            break;

        case "NAPTR":
            var order = divData.attr("data-record-order");
            var preference = divData.attr("data-record-preference");
            var flags = divData.attr("data-record-flags");
            var services = divData.attr("data-record-services");
            var regexp = divData.attr("data-record-regexp");
            var replacement = divData.attr("data-record-replacement");

            var newOrder = $("#txtAddEditRecordDataNaptrOrder").val();
            if (newOrder === "") {
                showAlert("warning", "Missing!", "Please enter a suitable order.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataNaptrOrder").trigger("focus");
                return;
            }

            var newPreference = $("#txtAddEditRecordDataNaptrPreference").val();
            if (newPreference === "") {
                showAlert("warning", "Missing!", "Please enter a suitable preference.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataNaptrPreference").trigger("focus");
                return;
            }

            var newFlags = $("#txtAddEditRecordDataNaptrFlags").val();
            var newServices = $("#txtAddEditRecordDataNaptrServices").val();
            var newRegexp = $("#txtAddEditRecordDataNaptrRegExp").val();
            var newReplacement = $("#txtAddEditRecordDataNaptrReplacement").val();

            if (newReplacement === "")
                newReplacement = ".";

            apiUrl += "&naptrOrder=" + order + "&naptrNewOrder=" + newOrder + "&naptrPreference=" + preference + "&naptrNewPreference=" + newPreference + "&naptrFlags=" + encodeURIComponent(flags) + "&naptrNewFlags=" + encodeURIComponent(newFlags) + "&naptrServices=" + encodeURIComponent(services) + "&naptrNewServices=" + encodeURIComponent(newServices) + "&naptrRegexp=" + encodeURIComponent(regexp) + "&naptrNewRegexp=" + encodeURIComponent(newRegexp) + "&naptrReplacement=" + encodeURIComponent(replacement) + "&naptrNewReplacement=" + encodeURIComponent(newReplacement);
            break;

        case "DNAME":
            var dname = $("#txtAddEditRecordDataValue").val();
            if (dname === "") {
                showAlert("warning", "Missing!", "Please enter a domain name to update the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            apiUrl += "&dname=" + encodeURIComponent(dname);
            break;

        case "DS":
            var subDomainName = $("#txtAddEditRecordName").val();
            if ((subDomainName === "") || (subDomainName === "@")) {
                showAlert("warning", "Missing!", "Please enter a name for the DS record.", divAddEditRecordAlert);
                $("#txtAddEditRecordName").trigger("focus");
                return;
            }

            var keyTag = divData.attr("data-record-key-tag");
            var algorithm = divData.attr("data-record-algorithm");
            var digestType = divData.attr("data-record-digest-type");

            var newKeyTag = $("#txtAddEditRecordDataDsKeyTag").val();
            if (newKeyTag === "") {
                showAlert("warning", "Missing!", "Please enter the Key Tag value to update the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataDsKeyTag").trigger("focus");
                return;
            }

            var newAlgorithm = $("#optAddEditRecordDataDsAlgorithm").val();
            if ((newAlgorithm === null) || (newAlgorithm === "")) {
                showAlert("warning", "Missing!", "Please select an DNSSEC algorithm to update the record.", divAddEditRecordAlert);
                $("#optAddEditRecordDataDsAlgorithm").trigger("focus");
                return;
            }

            var newDigestType = $("#optAddEditRecordDataDsDigestType").val();
            if ((newDigestType === null) || (newDigestType === "")) {
                showAlert("warning", "Missing!", "Please select a Digest Type to update the record.", divAddEditRecordAlert);
                $("#optAddEditRecordDataDsDigestType").trigger("focus");
                return;
            }

            var digest = divData.attr("data-record-digest");

            var newDigest = $("#txtAddEditRecordDataDsDigest").val();
            if (newDigest === "") {
                showAlert("warning", "Missing!", "Please enter the Digest hash in hex string format to update the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataDsDigest").trigger("focus");
                return;
            }

            apiUrl += "&keyTag=" + keyTag + "&algorithm=" + algorithm + "&digestType=" + digestType + "&newKeyTag=" + newKeyTag + "&newAlgorithm=" + newAlgorithm + "&newDigestType=" + newDigestType + "&digest=" + encodeURIComponent(digest) + "&newDigest=" + encodeURIComponent(newDigest);
            break;

        case "SSHFP":
            var sshfpAlgorithm = divData.attr("data-record-algorithm");
            var sshfpFingerprintType = divData.attr("data-record-fingerprint-type");
            var sshfpFingerprint = divData.attr("data-record-fingerprint");

            var newSshfpAlgorithm = $("#optAddEditRecordDataSshfpAlgorithm").val();
            if ((newSshfpAlgorithm === null) || (newSshfpAlgorithm === "")) {
                showAlert("warning", "Missing!", "Please select an Algorithm to update the record.", divAddEditRecordAlert);
                $("#optAddEditRecordDataSshfpAlgorithm").trigger("focus");
                return;
            }

            var newSshfpFingerprintType = $("#optAddEditRecordDataSshfpFingerprintType").val();
            if ((newSshfpFingerprintType === null) || (newSshfpFingerprintType === "")) {
                showAlert("warning", "Missing!", "Please select a Fingerprint Type to update the record.", divAddEditRecordAlert);
                $("#optAddEditRecordDataSshfpFingerprintType").trigger("focus");
                return;
            }

            var newSshfpFingerprint = $("#txtAddEditRecordDataSshfpFingerprint").val();
            if (newSshfpFingerprint === "") {
                showAlert("warning", "Missing!", "Please enter the Fingerprint hash in hex string format to update the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSshfpFingerprint").trigger("focus");
                return;
            }

            apiUrl += "&sshfpAlgorithm=" + sshfpAlgorithm + "&newSshfpAlgorithm=" + newSshfpAlgorithm + "&sshfpFingerprintType=" + sshfpFingerprintType + "&newSshfpFingerprintType=" + newSshfpFingerprintType + "&sshfpFingerprint=" + encodeURIComponent(sshfpFingerprint) + "&newSshfpFingerprint=" + encodeURIComponent(newSshfpFingerprint);
            break;

        case "TLSA":
            var tlsaCertificateUsage = divData.attr("data-record-certificate-usage");
            var tlsaSelector = divData.attr("data-record-selector");
            var tlsaMatchingType = divData.attr("data-record-matching-type");
            var tlsaCertificateAssociationData = divData.attr("data-record-certificate-association-data");

            var newTlsaCertificateUsage = $("#optAddEditRecordDataTlsaCertificateUsage").val();
            if ((newTlsaCertificateUsage === null) || (newTlsaCertificateUsage === "")) {
                showAlert("warning", "Missing!", "Please select a Certificate Usage to update the record.", divAddEditRecordAlert);
                $("#optAddEditRecordDataTlsaCertificateUsage").trigger("focus");
                return;
            }

            var newTlsaSelector = $("#optAddEditRecordDataTlsaSelector").val();
            if ((newTlsaSelector === null) || (newTlsaSelector === "")) {
                showAlert("warning", "Missing!", "Please select a Selector to update the record.", divAddEditRecordAlert);
                $("#optAddEditRecordDataTlsaSelector").trigger("focus");
                return;
            }

            var newTlsaMatchingType = $("#optAddEditRecordDataTlsaMatchingType").val();
            if ((newTlsaMatchingType === null) || (newTlsaMatchingType === "")) {
                showAlert("warning", "Missing!", "Please select a Matching Type to update the record.", divAddEditRecordAlert);
                $("#optAddEditRecordDataTlsaMatchingType").trigger("focus");
                return;
            }

            var newTlsaCertificateAssociationData = $("#txtAddEditRecordDataTlsaCertificateAssociationData").val();
            if (newTlsaCertificateAssociationData === "") {
                showAlert("warning", "Missing!", "Please enter the Certificate Association Data to update the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataTlsaCertificateAssociationData").trigger("focus");
                return;
            }

            apiUrl += "&tlsaCertificateUsage=" + tlsaCertificateUsage + "&newTlsaCertificateUsage=" + newTlsaCertificateUsage + "&tlsaSelector=" + tlsaSelector + "&newTlsaSelector=" + newTlsaSelector + "&tlsaMatchingType=" + tlsaMatchingType + "&newTlsaMatchingType=" + newTlsaMatchingType + "&tlsaCertificateAssociationData=" + encodeURIComponent(tlsaCertificateAssociationData) + "&newTlsaCertificateAssociationData=" + encodeURIComponent(newTlsaCertificateAssociationData);
            break;

        case "SVCB":
        case "HTTPS":
            var svcPriority = divData.attr("data-record-svc-priority");
            var svcTargetName = divData.attr("data-record-svc-target-name");
            var svcParams = "";
            {
                var jsonSvcParams = JSON.parse(divData.attr("data-record-svc-params"));

                for (var paramKey in jsonSvcParams) {
                    if (svcParams.length === 0)
                        svcParams = paramKey + "|" + jsonSvcParams[paramKey];
                    else
                        svcParams += "|" + paramKey + "|" + jsonSvcParams[paramKey];
                }

                if (svcParams.length === 0)
                    svcParams = false;
            }

            var newSvcPriority = $("#txtAddEditRecordDataSvcbPriority").val();
            if ((newSvcPriority === null) || (newSvcPriority === "")) {
                showAlert("warning", "Missing!", "Please enter a Priority value to update the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSvcbPriority").trigger("focus");
                return;
            }

            var newSvcTargetName = $("#txtAddEditRecordDataSvcbTargetName").val();
            if ((newSvcTargetName === null) || (newSvcTargetName === "")) {
                showAlert("warning", "Missing!", "Please enter a Target Name to update the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataSvcbTargetName").trigger("focus");
                return;
            }

            var newSvcParams = serializeTableData($("#tableAddEditRecordDataSvcbParams"), 2, divAddEditRecordAlert);
            if (newSvcParams === false)
                return;

            if (newSvcParams.length === 0)
                newSvcParams = false;

            var autoIpv4Hint = $("#chkAddEditRecordDataSvcbAutoIpv4Hint").prop("checked");
            var autoIpv6Hint = $("#chkAddEditRecordDataSvcbAutoIpv6Hint").prop("checked");

            apiUrl += "&svcPriority=" + svcPriority + "&newSvcPriority=" + newSvcPriority + "&svcTargetName=" + encodeURIComponent(svcTargetName) + "&newSvcTargetName=" + encodeURIComponent(newSvcTargetName) + "&svcParams=" + encodeURIComponent(svcParams) + "&newSvcParams=" + encodeURIComponent(newSvcParams) + "&autoIpv4Hint=" + autoIpv4Hint + "&autoIpv6Hint=" + autoIpv6Hint;
            break;

        case "URI":
            var uriPriority = divData.attr("data-record-priority");

            var newUriPriority = $("#txtAddEditRecordDataUriPriority").val();
            if (newUriPriority === "") {
                showAlert("warning", "Missing!", "Please enter a suitable priority.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataUriPriority").trigger("focus");
                return;
            }

            var uriWeight = divData.attr("data-record-weight");

            var newUriWeight = $("#txtAddEditRecordDataUriWeight").val();
            if (newUriWeight === "") {
                showAlert("warning", "Missing!", "Please enter a suitable weight.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataUriWeight").trigger("focus");
                return;
            }

            var uri = divData.attr("data-record-uri");

            var newUri = $("#txtAddEditRecordDataUri").val();
            if (newUri === "") {
                showAlert("warning", "Missing!", "Please enter a suitable value into the URI field.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataUri").trigger("focus");
                return;
            }

            apiUrl += "&uriPriority=" + uriPriority + "&newUriPriority=" + newUriPriority + "&uriWeight=" + uriWeight + "&newUriWeight=" + newUriWeight + "&uri=" + encodeURIComponent(uri) + "&newUri=" + encodeURIComponent(newUri);
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

            var value = divData.attr("data-record-value");

            var newValue = $("#txtAddEditRecordDataCaaValue").val();
            if (newValue === "") {
                showAlert("warning", "Missing!", "Please enter a suitable value into the authority field.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataCaaValue").trigger("focus");
                return;
            }

            apiUrl += "&flags=" + flags + "&tag=" + encodeURIComponent(tag) + "&newFlags=" + newFlags + "&newTag=" + encodeURIComponent(newTag) + "&value=" + encodeURIComponent(value) + "&newValue=" + encodeURIComponent(newValue);
            break;

        case "ANAME":
            var aname = divData.attr("data-record-aname");

            var newAName = $("#txtAddEditRecordDataValue").val();
            if (newAName === "") {
                showAlert("warning", "Missing!", "Please enter a suitable value to update the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            apiUrl += "&aname=" + encodeURIComponent(aname) + "&newAName=" + encodeURIComponent(newAName);
            break;

        case "FWD":
            var protocol = divData.attr("data-record-protocol");
            var newProtocol = $("input[name=rdAddEditRecordDataForwarderProtocol]:checked").val();

            var forwarder = divData.attr("data-record-forwarder");

            var newForwarder = $("#txtAddEditRecordDataForwarder").val();
            if (newForwarder === "") {
                showAlert("warning", "Missing!", "Please enter a domain name or IP address or URL as a forwarder to update the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataForwarder").trigger("focus");
                return;
            }

            var forwarderPriority = $("#txtAddEditRecordDataForwarderPriority").val();
            var dnssecValidation = $("#chkAddEditRecordDataForwarderDnssecValidation").prop("checked");

            apiUrl += "&protocol=" + protocol + "&newProtocol=" + newProtocol + "&forwarder=" + encodeURIComponent(forwarder) + "&newForwarder=" + encodeURIComponent(newForwarder) + "&forwarderPriority=" + forwarderPriority + "&dnssecValidation=" + dnssecValidation;

            if (newForwarder !== "this-server") {
                var proxyType = $("input[name=rdAddEditRecordDataForwarderProxyType]:checked").val();

                apiUrl += "&proxyType=" + proxyType;

                switch (proxyType) {
                    case "Http":
                    case "Socks5":
                        var proxyAddress = $("#txtAddEditRecordDataForwarderProxyAddress").val();
                        var proxyPort = $("#txtAddEditRecordDataForwarderProxyPort").val();
                        var proxyUsername = $("#txtAddEditRecordDataForwarderProxyUsername").val();
                        var proxyPassword = $("#txtAddEditRecordDataForwarderProxyPassword").val();

                        if ((proxyAddress == null) || (proxyAddress === "")) {
                            showAlert("warning", "Missing!", "Please enter a domain name or IP address for Proxy Server Address to update the record.", divAddEditRecordAlert);
                            $("#txtAddEditRecordDataForwarderProxyAddress").trigger("focus");
                            return;
                        }

                        if ((proxyPort == null) || (proxyPort === "")) {
                            showAlert("warning", "Missing!", "Please enter a port number for Proxy Server Port to update the record.", divAddEditRecordAlert);
                            $("#txtAddEditRecordDataForwarderProxyPort").trigger("focus");
                            return;
                        }

                        apiUrl += "&proxyAddress=" + encodeURIComponent(proxyAddress) + "&proxyPort=" + proxyPort + "&proxyUsername=" + encodeURIComponent(proxyUsername) + "&proxyPassword=" + encodeURIComponent(proxyPassword);
                        break;
                }
            }
            break;

        case "APP":
            apiUrl += "&appName=" + encodeURIComponent(divData.attr("data-record-app-name")) + "&classPath=" + encodeURIComponent(divData.attr("data-record-classpath")) + "&recordData=" + encodeURIComponent($("#txtAddEditRecordDataData").val());
            break;

        default:
            type = $("#txtAddEditRecordDataUnknownType").val();
            var rdata = divData.attr("data-record-rdata");

            var newRData = $("#txtAddEditRecordDataValue").val();
            if ((newRData === null) || (newRData === "")) {
                showAlert("warning", "Missing!", "Please enter a hex value as the RDATA to update the record.", divAddEditRecordAlert);
                $("#txtAddEditRecordDataValue").trigger("focus");
                return;
            }

            apiUrl += "&rdata=" + encodeURIComponent(rdata) + "&newRData=" + encodeURIComponent(newRData);
            break;
    }

    var node = $("#optZonesClusterNode").val();

    apiUrl = "api/zones/records/update?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&type=" + encodeURIComponent(type) + "&domain=" + encodeURIComponent(domain) + "&newDomain=" + encodeURIComponent(newDomain) + "&ttl=" + ttl + "&disable=" + disable + "&comments=" + encodeURIComponent(comments) + "&expiryTtl=" + expiryTtl + apiUrl;

    btn.button("loading");

    HTTPRequest({
        url: apiUrl + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            $("#modalAddEditRecord").modal("hide");

            //update local data
            editZoneInfo = responseJSON.response.zone;
            responseJSON.response.updatedRecord.index = recordIndex; //keep record index for update tasks
            editZoneRecords[recordIndex] = responseJSON.response.updatedRecord;

            if ((domain.toLowerCase() !== newDomain.toLowerCase()) && ($("#txtEditZoneFilterName").val() != "")) {
                //domain updated and filters applied
                editZoneFilteredRecords = null; //to evaluate filters again

                //show page
                showEditZonePage();
            }
            else {
                editZoneFilteredRecords[index] = responseJSON.response.updatedRecord;

                //show updated record
                var zoneType;
                if (responseJSON.response.zone.internal)
                    zoneType = "Internal";
                else
                    zoneType = responseJSON.response.zone.type;

                var tableHtmlRow = getZoneRecordRowHtml(index, zone, zoneType, responseJSON.response.updatedRecord);
                $("#trZoneRecord" + index).replaceWith(tableHtmlRow);
            }

            showAlert("success", "Record Updated!", "Resource record was updated successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            $("#modalAddEditRecord").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divAddEditRecordAlert
    });
}

function updateRecordState(objBtn, disable) {
    var btn = $(objBtn);
    var index = Number(btn.attr("data-id"));
    var divData = $("#data" + index);

    var zone = $("#titleEditZone").attr("data-zone");
    var recordIndex = Number(divData.attr("data-record-index"));
    var type = divData.attr("data-record-type");
    var domain = divData.attr("data-record-name");
    var ttl = divData.attr("data-record-ttl");
    var comments = divData.attr("data-record-comments");
    var expiryTtl = $("#txtAddEditRecordExpiryTtl").val();

    if (domain === "")
        domain = ".";

    if (disable && !confirm("Are you sure to disable the " + type + " record '" + domain + "'?"))
        return;

    var node = $("#optZonesClusterNode").val();

    var apiUrl = "api/zones/records/update?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&type=" + encodeURIComponent(type) + "&domain=" + encodeURIComponent(domain) + "&ttl=" + ttl + "&disable=" + disable + "&comments=" + encodeURIComponent(comments) + "&expiryTtl=" + expiryTtl;

    switch (type) {
        case "A":
        case "AAAA":
            var updateSvcbHints = zoneHasSvcbAutoHint(type == "A", type == "AAAA");

            apiUrl += "&ipAddress=" + encodeURIComponent(divData.attr("data-record-ip-address")) + "&updateSvcbHints=" + updateSvcbHints;
            break;

        case "NS":
            apiUrl += "&nameServer=" + encodeURIComponent(divData.attr("data-record-name-server")) + "&glue=" + encodeURIComponent(divData.attr("data-record-glue"));
            break;

        case "CNAME":
            apiUrl += "&cname=" + encodeURIComponent(divData.attr("data-record-cname"));
            break;

        case "PTR":
            apiUrl += "&ptrName=" + encodeURIComponent(divData.attr("data-record-ptr-name"));
            break;

        case "MX":
            apiUrl += "&preference=" + divData.attr("data-record-preference") + "&exchange=" + encodeURIComponent(divData.attr("data-record-exchange"));
            break;

        case "TXT":
            apiUrl += "&text=" + encodeURIComponent(divData.attr("data-record-text")) + "&splitText=" + divData.attr("data-record-split-text");
            break;

        case "RP":
            apiUrl += "&mailbox=" + encodeURIComponent(divData.attr("data-record-mailbox")) + "&txtDomain=" + encodeURIComponent(divData.attr("data-record-txt-domain"));
            break;

        case "SRV":
            apiUrl += "&priority=" + divData.attr("data-record-priority") + "&weight=" + divData.attr("data-record-weight") + "&port=" + divData.attr("data-record-port") + "&target=" + encodeURIComponent(divData.attr("data-record-target"));
            break;

        case "NAPTR":
            apiUrl += "&naptrOrder=" + divData.attr("data-record-order") + "&naptrPreference=" + divData.attr("data-record-preference") + "&naptrFlags=" + encodeURIComponent(divData.attr("data-record-flags")) + "&naptrServices=" + encodeURIComponent(divData.attr("data-record-services")) + "&naptrRegexp=" + encodeURIComponent(divData.attr("data-record-regexp")) + "&naptrReplacement=" + encodeURIComponent(divData.attr("data-record-replacement"));
            break;

        case "DNAME":
            apiUrl += "&dname=" + encodeURIComponent(divData.attr("data-record-dname"));
            break;

        case "DS":
            apiUrl += "&keyTag=" + divData.attr("data-record-key-tag") + "&algorithm=" + divData.attr("data-record-algorithm") + "&digestType=" + divData.attr("data-record-digest-type") + "&digest=" + encodeURIComponent(divData.attr("data-record-digest"));
            break;

        case "SSHFP":
            apiUrl += "&sshfpAlgorithm=" + divData.attr("data-record-algorithm") + "&sshfpFingerprintType=" + divData.attr("data-record-fingerprint-type") + "&sshfpFingerprint=" + encodeURIComponent(divData.attr("data-record-fingerprint"));
            break;

        case "TLSA":
            apiUrl += "&tlsaCertificateUsage=" + divData.attr("data-record-certificate-usage") + "&tlsaSelector=" + divData.attr("data-record-selector") + "&tlsaMatchingType=" + divData.attr("data-record-matching-type") + "&tlsaCertificateAssociationData=" + encodeURIComponent(divData.attr("data-record-certificate-association-data"));
            break;

        case "SVCB":
        case "HTTPS":
            var svcPriority = divData.attr("data-record-svc-priority");
            var svcTargetName = divData.attr("data-record-svc-target-name");
            var svcParams = "";
            {
                var jsonSvcParams = JSON.parse(divData.attr("data-record-svc-params"));

                for (var paramKey in jsonSvcParams) {
                    if (svcParams.length == 0)
                        svcParams = paramKey + "|" + jsonSvcParams[paramKey];
                    else
                        svcParams += "|" + paramKey + "|" + jsonSvcParams[paramKey];
                }

                if (svcParams.length === 0)
                    svcParams = false;
            }

            var autoIpv4Hint = divData.attr("data-record-auto-ipv4hint");
            var autoIpv6Hint = divData.attr("data-record-auto-ipv6hint");

            apiUrl += "&svcPriority=" + svcPriority + "&svcTargetName=" + encodeURIComponent(svcTargetName) + "&svcParams=" + encodeURIComponent(svcParams) + "&autoIpv4Hint=" + autoIpv4Hint + "&autoIpv6Hint=" + autoIpv6Hint;
            break;

        case "URI":
            apiUrl += "&uriPriority=" + divData.attr("data-record-priority") + "&uriWeight=" + encodeURIComponent(divData.attr("data-record-weight")) + "&uri=" + encodeURIComponent(divData.attr("data-record-uri"));
            break;

        case "CAA":
            apiUrl += "&flags=" + divData.attr("data-record-flags") + "&tag=" + encodeURIComponent(divData.attr("data-record-tag")) + "&value=" + encodeURIComponent(divData.attr("data-record-value"));
            break;

        case "ANAME":
            apiUrl += "&aname=" + encodeURIComponent(divData.attr("data-record-aname"));
            break;

        case "FWD":
            apiUrl += "&protocol=" + divData.attr("data-record-protocol") + "&forwarder=" + encodeURIComponent(divData.attr("data-record-forwarder"));

            var proxyType = divData.attr("data-record-proxy-type");

            apiUrl += "&forwarderPriority=" + divData.attr("data-record-priority") + "&dnssecValidation=" + divData.attr("data-record-dnssec-validation") + "&proxyType=" + proxyType;

            switch (proxyType) {
                case "Http":
                case "Socks5":
                    apiUrl += "&proxyAddress=" + encodeURIComponent(divData.attr("data-record-proxy-address")) + "&proxyPort=" + divData.attr("data-record-proxy-port") + "&proxyUsername=" + encodeURIComponent(divData.attr("data-record-proxy-username")) + "&proxyPassword=" + encodeURIComponent(divData.attr("data-record-proxy-password"));
                    break;
            }
            break;

        case "APP":
            apiUrl += "&appName=" + encodeURIComponent(divData.attr("data-record-app-name")) + "&classPath=" + encodeURIComponent(divData.attr("data-record-classpath")) + "&recordData=" + encodeURIComponent(divData.attr("data-record-data"));
            break;

        default:
            apiUrl += "&rdata=" + encodeURIComponent(divData.attr("data-record-rdata"));
            break;
    }

    btn.button("loading");

    HTTPRequest({
        url: apiUrl + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            btn.button("reset");

            //update local data
            editZoneInfo = responseJSON.response.zone;
            responseJSON.response.updatedRecord.index = recordIndex; //keep record index for update tasks
            editZoneRecords[recordIndex] = responseJSON.response.updatedRecord;
            editZoneFilteredRecords[index] = responseJSON.response.updatedRecord;

            //show updated record
            var zoneType;
            if (responseJSON.response.zone.internal)
                zoneType = "Internal";
            else
                zoneType = responseJSON.response.zone.type;

            var tableHtmlRow = getZoneRecordRowHtml(index, zone, zoneType, responseJSON.response.updatedRecord);
            $("#trZoneRecord" + index).replaceWith(tableHtmlRow);

            if (disable)
                showAlert("success", "Record Disabled!", "Resource record was disabled successfully.");
            else
                showAlert("success", "Record Enabled!", "Resource record was enabled successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function deleteRecord(objBtn) {
    var btn = $(objBtn);
    var index = btn.attr("data-id");
    var divData = $("#data" + index);

    var zone = $("#titleEditZone").attr("data-zone");
    var recordIndex = Number(divData.attr("data-record-index"));
    var domain = divData.attr("data-record-name");
    var type = divData.attr("data-record-type");

    if (domain === "")
        domain = ".";

    if (!confirm("Are you sure to permanently delete the " + type + " record '" + domain + "'?"))
        return;

    var node = $("#optZonesClusterNode").val();

    var apiUrl = "api/zones/records/delete?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&domain=" + encodeURIComponent(domain) + "&type=" + encodeURIComponent(type);

    switch (type) {
        case "A":
        case "AAAA":
            var updateSvcbHints = zoneHasSvcbAutoHint(type == "A", type == "AAAA");

            apiUrl += "&ipAddress=" + encodeURIComponent(divData.attr("data-record-ip-address")) + "&updateSvcbHints=" + updateSvcbHints;
            break;

        case "NS":
            apiUrl += "&nameServer=" + encodeURIComponent(divData.attr("data-record-name-server"));
            break;

        case "PTR":
            apiUrl += "&ptrName=" + encodeURIComponent(divData.attr("data-record-ptr-name"));
            break;

        case "MX":
            apiUrl += "&preference=" + divData.attr("data-record-preference") + "&exchange=" + encodeURIComponent(divData.attr("data-record-exchange"));
            break;

        case "TXT":
            apiUrl += "&text=" + encodeURIComponent(divData.attr("data-record-text")) + "&splitText=" + divData.attr("data-record-split-text");
            break;

        case "RP":
            apiUrl += "&mailbox=" + encodeURIComponent(divData.attr("data-record-mailbox")) + "&txtDomain=" + encodeURIComponent(divData.attr("data-record-txt-domain"));
            break;

        case "SRV":
            apiUrl += "&priority=" + divData.attr("data-record-priority") + "&weight=" + divData.attr("data-record-weight") + "&port=" + divData.attr("data-record-port") + "&target=" + encodeURIComponent(divData.attr("data-record-target"));
            break;

        case "NAPTR":
            apiUrl += "&naptrOrder=" + divData.attr("data-record-order") + "&naptrPreference=" + divData.attr("data-record-preference") + "&naptrFlags=" + encodeURIComponent(divData.attr("data-record-flags")) + "&naptrServices=" + encodeURIComponent(divData.attr("data-record-services")) + "&naptrRegexp=" + encodeURIComponent(divData.attr("data-record-regexp")) + "&naptrReplacement=" + encodeURIComponent(divData.attr("data-record-replacement"));
            break;

        case "DS":
            apiUrl += "&keyTag=" + divData.attr("data-record-key-tag") + "&algorithm=" + divData.attr("data-record-algorithm") + "&digestType=" + divData.attr("data-record-digest-type") + "&digest=" + encodeURIComponent(divData.attr("data-record-digest"));
            break;

        case "SSHFP":
            apiUrl += "&sshfpAlgorithm=" + divData.attr("data-record-algorithm") + "&sshfpFingerprintType=" + divData.attr("data-record-fingerprint-type") + "&sshfpFingerprint=" + encodeURIComponent(divData.attr("data-record-fingerprint"));
            break;

        case "TLSA":
            apiUrl += "&tlsaCertificateUsage=" + divData.attr("data-record-certificate-usage") + "&tlsaSelector=" + divData.attr("data-record-selector") + "&tlsaMatchingType=" + divData.attr("data-record-matching-type") + "&tlsaCertificateAssociationData=" + encodeURIComponent(divData.attr("data-record-certificate-association-data"));
            break;

        case "SVCB":
        case "HTTPS":
            var svcPriority = divData.attr("data-record-svc-priority");
            var svcTargetName = divData.attr("data-record-svc-target-name");
            var svcParams = "";
            {
                var jsonSvcParams = JSON.parse(divData.attr("data-record-svc-params"));

                for (var paramKey in jsonSvcParams) {
                    if (svcParams.length == 0)
                        svcParams = paramKey + "|" + jsonSvcParams[paramKey];
                    else
                        svcParams += "|" + paramKey + "|" + jsonSvcParams[paramKey];
                }

                if (svcParams.length === 0)
                    svcParams = false;
            }

            apiUrl += "&svcPriority=" + svcPriority + "&svcTargetName=" + encodeURIComponent(svcTargetName) + "&svcParams=" + encodeURIComponent(svcParams);
            break;

        case "URI":
            apiUrl += "&uriPriority=" + divData.attr("data-record-priority") + "&uriWeight=" + encodeURIComponent(divData.attr("data-record-weight")) + "&uri=" + encodeURIComponent(divData.attr("data-record-uri"));
            break;

        case "CAA":
            apiUrl += "&flags=" + divData.attr("data-record-flags") + "&tag=" + encodeURIComponent(divData.attr("data-record-tag")) + "&value=" + encodeURIComponent(divData.attr("data-record-value"));
            break;

        case "ANAME":
            apiUrl += "&aname=" + encodeURIComponent(divData.attr("data-record-aname"));
            break;

        case "FWD":
            apiUrl += "&protocol=" + divData.attr("data-record-protocol") + "&forwarder=" + encodeURIComponent(divData.attr("data-record-forwarder"));
            break;

        default:
            var rdata = divData.attr("data-record-rdata");
            if (rdata != null)
                apiUrl += "&rdata=" + encodeURIComponent(rdata);
    }

    btn.button("loading");

    HTTPRequest({
        url: apiUrl + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            //update local array
            editZoneRecords.splice(recordIndex, 1);
            editZoneFilteredRecords = null; //to evaluate filters again

            //show page
            showEditZonePage();

            showAlert("success", "Record Deleted!", "Resource record was deleted successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function showSignZoneModal(zoneName) {
    $("#divDnssecSignZoneAlert").html("");
    $("#lblDnssecSignZoneZoneName").text(zoneName === "." ? "<root>" : zoneName);
    $("#lblDnssecSignZoneZoneName").attr("data-zone", zoneName);
    $("#rdDnssecSignZoneAlgorithmEcdsa").prop("checked", true);

    $("#divDnssecSignZoneRsaParameters").hide();
    $("#optDnssecSignZoneRsaHashAlgorithm").val("SHA256");

    $("#divDnssecSignZoneEcdsaParameters").show();
    $("#optDnssecSignZoneEcdsaCurve").val("P256");

    $("#divDnssecSignZoneEddsaParameters").hide();
    $("#optDnssecSignZoneEddsaCurve").val("ED25519");

    $("#rdDnssecSignZoneKskGenerationAutomatic").prop("checked", true)
    $("#divDnssecSignZoneRsaKskKeySize").hide();
    $("#optDnssecSignZoneRsaKskKeySize").val("2048");
    $("#divDnssecSignZonePemKskPrivateKey").hide();
    $("#txtDnssecSignZonePemKskPrivateKey").val("");

    $("#rdDnssecSignZoneZskGenerationAutomatic").prop("checked", true)
    $("#divDnssecSignZoneRsaZskKeySize").hide();
    $("#optDnssecSignZoneRsaZskKeySize").val("1280");
    $("#divDnssecSignZonePemZskPrivateKey").hide();
    $("#txtDnssecSignZonePemZskPrivateKey").val("");

    $("#rdDnssecSignZoneNxProofNSEC").prop("checked", true);

    $("#divDnssecSignZoneNSEC3Parameters").hide();
    $("#txtDnssecSignZoneNSEC3Iterations").val("0");
    $("#txtDnssecSignZoneNSEC3SaltLength").val("0");

    $("#txtDnssecSignZoneDnsKeyTtl").val("3600");
    $("#txtDnssecSignZoneZskAutoRollover").val("30");

    $("#modalDnssecSignZone").modal("show");
}

function signPrimaryZone() {
    var divDnssecSignZoneAlert = $("#divDnssecSignZoneAlert");
    var zone = $("#lblDnssecSignZoneZoneName").attr("data-zone");
    var algorithm = $("input[name=rdDnssecSignZoneAlgorithm]:checked").val();
    var pemKskPrivateKey = $("#txtDnssecSignZonePemKskPrivateKey").val();
    var pemZskPrivateKey = $("#txtDnssecSignZonePemZskPrivateKey").val();
    var dnsKeyTtl = $("#txtDnssecSignZoneDnsKeyTtl").val();
    var zskRolloverDays = $("#txtDnssecSignZoneZskAutoRollover").val();
    var nxProof = $("input[name=rdDnssecSignZoneNxProof]:checked").val();

    var additionalParameters = "";

    if (nxProof === "NSEC3") {
        var iterations = $("#txtDnssecSignZoneNSEC3Iterations").val();
        var saltLength = $("#txtDnssecSignZoneNSEC3SaltLength").val();

        additionalParameters += "&iterations=" + iterations + "&saltLength=" + saltLength;
    }

    switch (algorithm) {
        case "RSA":
            var hashAlgorithm = $("#optDnssecSignZoneRsaHashAlgorithm").val();
            var kskKeySize = $("#optDnssecSignZoneRsaKskKeySize").val();
            var zskKeySize = $("#optDnssecSignZoneRsaZskKeySize").val();

            additionalParameters += "&hashAlgorithm=" + hashAlgorithm + "&kskKeySize=" + kskKeySize + "&zskKeySize=" + zskKeySize;
            break;

        case "ECDSA":
            var curve = $("#optDnssecSignZoneEcdsaCurve").val();

            additionalParameters += "&curve=" + curve;
            break;

        case "EDDSA":
            var curve = $("#optDnssecSignZoneEddsaCurve").val();

            additionalParameters += "&curve=" + curve;
            break;
    }

    var node = $("#optZonesClusterNode").val();

    var btn = $("#btnDnssecSignZone");
    btn.button("loading");

    HTTPRequest({
        url: "api/zones/dnssec/sign?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&algorithm=" + algorithm + "&pemKskPrivateKey=" + encodeURIComponent(pemKskPrivateKey) + "&pemZskPrivateKey=" + encodeURIComponent(pemZskPrivateKey) + "&dnsKeyTtl=" + dnsKeyTtl + "&zskRolloverDays=" + zskRolloverDays + "&nxProof=" + nxProof + additionalParameters + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            btn.button("reset");
            $("#modalDnssecSignZone").modal("hide");

            $("#txtDnssecSignZonePemKskPrivateKey").val("");
            $("#txtDnssecSignZonePemZskPrivateKey").val("");

            var zoneHideDnssecRecords = (localStorage.getItem("zoneHideDnssecRecords") == "true");
            if (zoneHideDnssecRecords) {
                $("#titleEditZoneDnssecStatus").removeClass();
                $("#titleEditZoneDnssecStatus").addClass("label label-primary");
                $("#titleEditZoneDnssecStatus").show();

                $("#lnkZoneDnssecSignZone").hide();

                $("#lnkZoneDnssecHideRecords").hide();
                $("#lnkZoneDnssecShowRecords").show();

                $("#lnkZoneDnssecViewDsRecords").show();
                $("#lnkZoneDnssecProperties").show();
                $("#lnkZoneDnssecUnsignZone").show();

                $("#optAddEditRecordTypeDs").show();
                $("#optAddEditRecordTypeSshfp").show();
                $("#optAddEditRecordTypeTlsa").show();
                $("#optAddEditRecordTypeAName").hide();
                $("#optAddEditRecordTypeApp").hide();
            }
            else {
                showEditZone(zone);
            }

            showAlert("success", "Zone Signed!", "The primary zone was signed successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalDnssecSignZone").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divDnssecSignZoneAlert
    });
}

function showUnsignZoneModal(zoneName) {
    $("#divDnssecUnsignZoneAlert").html("");
    $("#lblDnssecUnsignZoneZoneName").text(zoneName === "." ? "<root>" : zoneName);
    $("#lblDnssecUnsignZoneZoneName").attr("data-zone", zoneName);

    $("#modalDnssecUnsignZone").modal("show");
}

function unsignPrimaryZone() {
    var divDnssecUnsignZoneAlert = $("#divDnssecUnsignZoneAlert");
    var zone = $("#lblDnssecUnsignZoneZoneName").attr("data-zone");

    var node = $("#optZonesClusterNode").val();

    var btn = $("#btnDnssecUnsignZone");
    btn.button("loading");

    HTTPRequest({
        url: "api/zones/dnssec/unsign?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            btn.button("reset");
            $("#modalDnssecUnsignZone").modal("hide");

            var zoneHideDnssecRecords = (localStorage.getItem("zoneHideDnssecRecords") == "true");
            if (zoneHideDnssecRecords) {
                $("#titleEditZoneDnssecStatus").hide();

                $("#lnkZoneDnssecSignZone").show();

                $("#lnkZoneDnssecHideRecords").hide();
                $("#lnkZoneDnssecShowRecords").hide();

                $("#lnkZoneDnssecViewDsRecords").hide();
                $("#lnkZoneDnssecProperties").hide();
                $("#lnkZoneDnssecUnsignZone").hide();

                $("#optAddEditRecordTypeDs").hide();
                $("#optAddEditRecordTypeSshfp").hide();
                $("#optAddEditRecordTypeTlsa").hide();
                $("#optAddEditRecordTypeAName").show();
                $("#optAddEditRecordTypeApp").show();
            }
            else {
                showEditZone(zone);
            }

            showAlert("success", "Zone Unsigned!", "The primary zone was unsigned successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalDnssecUnsignZone").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divDnssecUnsignZoneAlert
    });
}

function showViewDsModal(zoneName) {
    var divDnssecViewDsAlert = $("#divDnssecViewDsAlert");
    var divDnssecViewDsLoader = $("#divDnssecViewDsLoader");
    var divDnssecViewDs = $("#divDnssecViewDs");
    var lblDnssecViewDsZoneName = $("#lblDnssecViewDsZoneName");

    divDnssecViewDsAlert.html("");
    lblDnssecViewDsZoneName.text(zoneName === "." ? "<root>" : zoneName);

    divDnssecViewDsLoader.show();
    divDnssecViewDs.hide();

    var node = $("#optZonesClusterNode").val();

    $("#modalDnssecViewDs").modal("show");

    HTTPRequest({
        url: "api/zones/dnssec/viewDS?token=" + sessionData.token + "&zone=" + encodeURIComponent(zoneName) + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            var tableHtmlRows = "";

            for (var i = 0; i < responseJSON.response.dsRecords.length; i++) {
                var rowspan = responseJSON.response.dsRecords[i].digests.length + 1;

                tableHtmlRows += "<tr>"
                    + "<td rowspan=" + rowspan + ">" + responseJSON.response.dsRecords[i].keyTag + "</td>"
                    + "<td rowspan=" + rowspan + ">" + responseJSON.response.dsRecords[i].dnsKeyState;

                if ((responseJSON.response.dsRecords[i].dnsKeyState === "Active") && responseJSON.response.dsRecords[i].isRetiring)
                    tableHtmlRows += " (retiring)";

                if (responseJSON.response.dsRecords[i].dnsKeyStateReadyBy != null)
                    tableHtmlRows += "</br>(ready by: " + moment(responseJSON.response.dsRecords[i].dnsKeyStateReadyBy).local().format("YYYY-MM-DD HH:mm") + ")";

                tableHtmlRows += "</td><td rowspan=" + rowspan + ">" + responseJSON.response.dsRecords[i].algorithm + " (" + responseJSON.response.dsRecords[i].algorithmNumber + ")</td>";

                for (var j = 0; j < responseJSON.response.dsRecords[i].digests.length; j++) {
                    if (j > 0)
                        tableHtmlRows += "<tr>";

                    tableHtmlRows += "<td>" + responseJSON.response.dsRecords[i].digests[j].digestType + " (" + responseJSON.response.dsRecords[i].digests[j].digestTypeNumber + ")</td><td style=\"word-break: break-all;\">" + responseJSON.response.dsRecords[i].digests[j].digest + "</td>";
                    tableHtmlRows += "</tr>";
                }

                tableHtmlRows += "<tr><td colspan=\"2\" style=\"word-break: break-all;\"><b>Public Key</b></br>" + responseJSON.response.dsRecords[i].publicKey + "</td></tr>";
            }

            $("#tableDnssecViewDsBody").html(tableHtmlRows);

            divDnssecViewDsLoader.hide();
            divDnssecViewDs.show();
        },
        error: function () {
            divDnssecViewDsLoader.hide();
        },
        invalidToken: function () {
            $("#modalDnssecViewDs").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divDnssecViewDsAlert,
        objLoaderPlaceholder: divDnssecViewDsLoader
    });
}

function showDnssecPropertiesModal(zoneName) {
    var divDnssecPropertiesLoader = $("#divDnssecPropertiesLoader");
    var divDnssecProperties = $("#divDnssecProperties");

    $("#divDnssecPropertiesAlert").html("");
    $("#lblDnssecPropertiesZoneName").text(zoneName === "." ? "<root>" : zoneName);
    $("#lblDnssecPropertiesZoneName").attr("data-zone", zoneName);

    $("#divDnssecPropertiesAddKey").collapse("hide");
    $("#optDnssecPropertiesAddKeyKeyType").val("KeySigningKey");
    $("#optDnssecPropertiesAddKeyAlgorithm").val("ECDSA");

    $("#divDnssecPropertiesAddKeyRsaParameters").hide();
    $("#optDnssecPropertiesAddKeyRsaHashAlgorithm").val("SHA256");

    $("#divDnssecPropertiesAddKeyEcdsaParameters").show();
    $("#optDnssecPropertiesAddKeyEcdsaCurve").val("P256");

    $("#divDnssecPropertiesAddKeyEddsaParameters").hide();
    $("#optDnssecPropertiesAddKeyEddsaCurve").val("ED25519");

    $("#rdDnssecPropertiesKeyGenerationAutomatic").prop("checked", true);
    $("#divDnssecPropertiesAddKeyRsaKeySize").hide();
    $("#optDnssecPropertiesAddKeyRsaKeySize").val("1024");
    $("#divDnssecPropertiesPemPrivateKey").hide();

    $("#divDnssecPropertiesAddKeyAutomaticRollover").hide();
    $("#txtDnssecPropertiesAddKeyAutomaticRollover").val(0);

    divDnssecPropertiesLoader.show();
    divDnssecProperties.hide();

    $("#modalDnssecProperties").modal("show");

    refreshDnssecProperties(divDnssecPropertiesLoader);
}

function refreshDnssecProperties(divDnssecPropertiesLoader) {
    var divDnssecPropertiesAlert = $("#divDnssecPropertiesAlert");
    var zone = $("#lblDnssecPropertiesZoneName").attr("data-zone");
    var divDnssecPropertiesNoteReadyBy = $("#divDnssecPropertiesNoteReadyBy");
    var divDnssecPropertiesNoteActiveBy = $("#divDnssecPropertiesNoteActiveBy");
    var divDnssecPropertiesNoteRetiredRevoked = $("#divDnssecPropertiesNoteRetiredRevoked");

    var node = $("#optZonesClusterNode").val();

    divDnssecPropertiesNoteReadyBy.hide();
    divDnssecPropertiesNoteActiveBy.hide();
    divDnssecPropertiesNoteRetiredRevoked.hide();

    HTTPRequest({
        url: "api/zones/dnssec/properties/get?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            var tableHtmlRows = "";
            var foundGeneratedKey = false;

            for (var i = 0; i < responseJSON.response.dnssecPrivateKeys.length; i++) {
                var id = Math.floor(Math.random() * 10000);

                tableHtmlRows += "<tr id=\"trDnssecPropertiesPrivateKey" + id + "\">"
                    + "<td>" + responseJSON.response.dnssecPrivateKeys[i].keyTag + "</td>"
                    + "<td>" + responseJSON.response.dnssecPrivateKeys[i].keyType + "</td>"
                    + "<td>" + responseJSON.response.dnssecPrivateKeys[i].algorithm + " (" + responseJSON.response.dnssecPrivateKeys[i].algorithmNumber + ")</td>"
                    + "<td>" + responseJSON.response.dnssecPrivateKeys[i].state + ((responseJSON.response.dnssecPrivateKeys[i].state === "Active") && responseJSON.response.dnssecPrivateKeys[i].isRetiring ? " (retiring)" : "") + "</td>"
                    + "<td>" + moment(responseJSON.response.dnssecPrivateKeys[i].stateChangedOn).local().format("YYYY-MM-DD HH:mm");

                if (responseJSON.response.dnssecPrivateKeys[i].stateReadyBy != null)
                    tableHtmlRows += "</br>(ready by: " + moment(responseJSON.response.dnssecPrivateKeys[i].stateReadyBy).local().format("YYYY-MM-DD HH:mm") + ")";
                else if (responseJSON.response.dnssecPrivateKeys[i].stateActiveBy != null)
                    tableHtmlRows += "</br>(active by: " + moment(responseJSON.response.dnssecPrivateKeys[i].stateActiveBy).local().format("YYYY-MM-DD HH:mm") + ")";

                tableHtmlRows += "</td><td>";

                if (responseJSON.response.dnssecPrivateKeys[i].keyType === "ZoneSigningKey") {
                    switch (responseJSON.response.dnssecPrivateKeys[i].state) {
                        case "Generated":
                        case "Published":
                        case "Ready":
                        case "Active":
                            if (responseJSON.response.dnssecPrivateKeys[i].isRetiring) {
                                tableHtmlRows += "-";
                            }
                            else {
                                tableHtmlRows += "<input id=\"txtDnssecPropertiesPrivateKeyAutomaticRollover" + id + "\" type=\"text\" placeholder=\"days\" style=\"width: 40px;\" value=\"" + responseJSON.response.dnssecPrivateKeys[i].rolloverDays + "\" />" +
                                    "<button type=\"button\" class=\"btn btn-default\" style=\"padding: 2px 6px; margin-top: -2px; margin-left: 4px; font-size: 12px; height: 26px; width: 46px;\" data-id=\"" + id + "\" data-loading-text=\"Save\" onclick=\"updateDnssecPrivateKey(" + responseJSON.response.dnssecPrivateKeys[i].keyTag + ", this);\">Save</button>";
                            }
                            break;

                        default:
                            tableHtmlRows += "-";
                            break;
                    }
                }
                else {
                    tableHtmlRows += "-";
                }

                tableHtmlRows += "</td>" +
                    "<td align=\"right\">";

                switch (responseJSON.response.dnssecPrivateKeys[i].state) {
                    case "Generated":
                        tableHtmlRows += "<div class=\"dropdown\"><a href=\"#\" id=\"btnDnssecPropertiesDnsKeyRowOption" + id + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
                        tableHtmlRows += "<li><a href=\"#\" onclick=\"deleteDnssecPrivateKey(" + responseJSON.response.dnssecPrivateKeys[i].keyTag + ", '" + id + "'); return false;\">Delete</a></li>";
                        tableHtmlRows += "</ul></div>";
                        foundGeneratedKey = true;
                        break;

                    case "Ready":
                    case "Active":
                        if (!responseJSON.response.dnssecPrivateKeys[i].isRetiring) {
                            tableHtmlRows += "<div class=\"dropdown\"><a href=\"#\" id=\"btnDnssecPropertiesDnsKeyRowOption" + id + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
                            tableHtmlRows += "<li><a href=\"#\" onclick=\"rolloverDnssecDnsKey(" + responseJSON.response.dnssecPrivateKeys[i].keyTag + ", '" + id + "'); return false;\">Rollover</a></li>";
                            tableHtmlRows += "<li><a href=\"#\" onclick=\"retireDnssecDnsKey(" + responseJSON.response.dnssecPrivateKeys[i].keyTag + ", '" + id + "'); return false;\">Retire</a></li>";
                            tableHtmlRows += "</ul></div>";
                        }
                        break;
                }

                tableHtmlRows += "</td></tr>";

                if (responseJSON.response.dnssecPrivateKeys[i].keyType === "KeySigningKey") {
                    switch (responseJSON.response.dnssecPrivateKeys[i].state) {
                        case "Published":
                            divDnssecPropertiesNoteReadyBy.show();
                            break;

                        case "Ready":
                            divDnssecPropertiesNoteActiveBy.show();
                            break;
                    }
                }

                switch (responseJSON.response.dnssecPrivateKeys[i].state) {
                    case "Retired":
                    case "Revoked":
                        divDnssecPropertiesNoteRetiredRevoked.show();
                        break;
                }
            }

            $("#tableDnssecPropertiesPrivateKeysBody").html(tableHtmlRows);
            $("#btnDnssecPropertiesPublishKeys").prop("disabled", !foundGeneratedKey);

            switch (responseJSON.response.dnssecStatus) {
                case "SignedWithNSEC":
                    $("#rdDnssecPropertiesNxProofNSEC").prop("checked", true);

                    $("#divDnssecPropertiesNSEC3Parameters").hide();
                    $("#txtDnssecPropertiesNSEC3Iterations").val(0);
                    $("#txtDnssecPropertiesNSEC3SaltLength").val(0);

                    $("#btnDnssecPropertiesChangeNxProof").attr("data-nx-proof", "NSEC");
                    break;

                case "SignedWithNSEC3":
                    $("#rdDnssecPropertiesNxProofNSEC3").prop("checked", true);

                    $("#divDnssecPropertiesNSEC3Parameters").show();
                    $("#txtDnssecPropertiesNSEC3Iterations").val(responseJSON.response.nsec3Iterations);
                    $("#txtDnssecPropertiesNSEC3SaltLength").val(responseJSON.response.nsec3SaltLength);

                    $("#btnDnssecPropertiesChangeNxProof").attr("data-nx-proof", "NSEC3");
                    $("#btnDnssecPropertiesChangeNxProof").attr("data-nsec3-iterations", responseJSON.response.nsec3Iterations);
                    $("#btnDnssecPropertiesChangeNxProof").attr("data-nsec3-salt-length", responseJSON.response.nsec3SaltLength);
                    break;
            }

            $("#txtDnssecPropertiesDnsKeyTtl").val(responseJSON.response.dnsKeyTtl);

            if (divDnssecPropertiesLoader != null)
                divDnssecPropertiesLoader.hide();

            $("#divDnssecProperties").show();
        },
        error: function () {
            if (divDnssecPropertiesLoader != null)
                divDnssecPropertiesLoader.hide();
        },
        invalidToken: function () {
            $("#modalDnssecProperties").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divDnssecPropertiesAlert,
        objLoaderPlaceholder: divDnssecPropertiesLoader
    });
}

function updateDnssecPrivateKey(keyTag, objBtn) {
    var btn = $(objBtn);
    var id = btn.attr("data-id");
    var divDnssecPropertiesAlert = $("#divDnssecPropertiesAlert");
    var zone = $("#lblDnssecPropertiesZoneName").attr("data-zone");
    var rolloverDays = $("#txtDnssecPropertiesPrivateKeyAutomaticRollover" + id).val();

    var node = $("#optZonesClusterNode").val();

    btn.button("loading");

    HTTPRequest({
        url: "api/zones/dnssec/properties/updatePrivateKey?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&keyTag=" + keyTag + "&rolloverDays=" + rolloverDays + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            btn.button("reset");
            showAlert("success", "Updated!", "The DNSKEY automatic rollover config was updated successfully.", divDnssecPropertiesAlert);
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalDnssecProperties").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divDnssecPropertiesAlert
    });
}

function deleteDnssecPrivateKey(keyTag, id) {
    if (!confirm("Are you sure to permanently delete the private key (" + keyTag + ")?"))
        return;

    var divDnssecPropertiesAlert = $("#divDnssecPropertiesAlert");
    var zone = $("#lblDnssecPropertiesZoneName").attr("data-zone");

    var node = $("#optZonesClusterNode").val();

    var btn = $("#btnDnssecPropertiesDnsKeyRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<img src='/img/loader-small.gif'/>");

    HTTPRequest({
        url: "api/zones/dnssec/properties/deletePrivateKey?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&keyTag=" + keyTag + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            $("#trDnssecPropertiesPrivateKey" + id).remove();
            showAlert("success", "Private Key Deleted!", "The DNSSEC private key was deleted successfully.", divDnssecPropertiesAlert);
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            $("#modalDnssecProperties").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divDnssecPropertiesAlert
    });
}

function rolloverDnssecDnsKey(keyTag, id) {
    if (!confirm("Are you sure you want to rollover the DNS Key (" + keyTag + ")?"))
        return;

    var divDnssecPropertiesAlert = $("#divDnssecPropertiesAlert");
    var zone = $("#lblDnssecPropertiesZoneName").attr("data-zone");

    var node = $("#optZonesClusterNode").val();

    var btn = $("#btnDnssecPropertiesDnsKeyRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<img src='/img/loader-small.gif'/>");

    HTTPRequest({
        url: "api/zones/dnssec/properties/rolloverDnsKey?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&keyTag=" + keyTag + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            refreshDnssecProperties();
            showAlert("success", "Rollover Done!", "The DNS Key was rolled over successfully.", divDnssecPropertiesAlert);
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            $("#modalDnssecProperties").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divDnssecPropertiesAlert
    });
}

function retireDnssecDnsKey(keyTag, id) {
    if (!confirm("Are you sure you want to retire the DNS Key (" + keyTag + ")?"))
        return;

    var divDnssecPropertiesAlert = $("#divDnssecPropertiesAlert");
    var zone = $("#lblDnssecPropertiesZoneName").attr("data-zone");

    var node = $("#optZonesClusterNode").val();

    var btn = $("#btnDnssecPropertiesDnsKeyRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<img src='/img/loader-small.gif'/>");

    HTTPRequest({
        url: "api/zones/dnssec/properties/retireDnsKey?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&keyTag=" + keyTag + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            refreshDnssecProperties();
            showAlert("success", "DNS Key Retired!", "The DNS Key was retired successfully.", divDnssecPropertiesAlert);
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            $("#modalDnssecProperties").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divDnssecPropertiesAlert
    });
}

function publishAllDnssecPrivateKeys(objBtn) {
    if (!confirm("Are you sure you want to publish all generated DNSSEC private keys?"))
        return;

    var btn = $(objBtn);
    var divDnssecPropertiesAlert = $("#divDnssecPropertiesAlert");
    var zone = $("#lblDnssecPropertiesZoneName").attr("data-zone");

    var node = $("#optZonesClusterNode").val();

    btn.button("loading");

    HTTPRequest({
        url: "api/zones/dnssec/properties/publishAllPrivateKeys?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            refreshDnssecProperties();
            btn.button("reset");
            showAlert("success", "Keys Published!", "All the generated DNSSEC private keys were published successfully.", divDnssecPropertiesAlert);
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalDnssecProperties").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divDnssecPropertiesAlert
    });
}

function addDnssecPrivateKey(objBtn) {
    var btn = $(objBtn);
    var divDnssecPropertiesAlert = $("#divDnssecPropertiesAlert");
    var zone = $("#lblDnssecPropertiesZoneName").attr("data-zone");
    var keyType = $("#optDnssecPropertiesAddKeyKeyType").val();
    var algorithm = $("#optDnssecPropertiesAddKeyAlgorithm").val();
    var pemPrivateKey = $("#txtDnssecPropertiesPemPrivateKey").val();
    var rolloverDays = $("#txtDnssecPropertiesAddKeyAutomaticRollover").val();

    var additionalParameters = "";

    switch (algorithm) {
        case "RSA":
            var hashAlgorithm = $("#optDnssecPropertiesAddKeyRsaHashAlgorithm").val();
            var keySize = $("#optDnssecPropertiesAddKeyRsaKeySize").val();

            additionalParameters = "&hashAlgorithm=" + hashAlgorithm + "&keySize=" + keySize;
            break;

        case "ECDSA":
            var curve = $("#optDnssecPropertiesAddKeyEcdsaCurve").val();

            additionalParameters = "&curve=" + curve;
            break;

        case "EDDSA":
            var curve = $("#optDnssecPropertiesAddKeyEddsaCurve").val();

            additionalParameters = "&curve=" + curve;
            break;
    }

    var node = $("#optZonesClusterNode").val();

    btn.button("loading");

    HTTPRequest({
        url: "api/zones/dnssec/properties/addPrivateKey?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&keyType=" + keyType + "&algorithm=" + algorithm + "&pemPrivateKey=" + encodeURIComponent(pemPrivateKey) + "&rolloverDays=" + rolloverDays + additionalParameters + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            $("#divDnssecPropertiesAddKey").collapse("hide");
            $("#txtDnssecPropertiesPemPrivateKey").val("");

            refreshDnssecProperties();
            btn.button("reset");

            showAlert("success", "Key Added!", "The DNSSEC private key was added successfully.", divDnssecPropertiesAlert);
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalDnssecProperties").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divDnssecPropertiesAlert
    });
}

function changeDnssecNxProof(objBtn) {
    var btn = $(objBtn);
    var currentNxProof = btn.attr("data-nx-proof");
    var currentIterations = btn.attr("data-nsec3-iterations");
    var currentSaltLength = btn.attr("data-nsec3-salt-length");

    var nxProof = $("input[name=rdDnssecPropertiesNxProof]:checked").val();
    var iterations;
    var saltLength;

    var divDnssecPropertiesAlert = $("#divDnssecPropertiesAlert");

    var zone = $("#lblDnssecPropertiesZoneName").attr("data-zone");
    var apiUrl;

    switch (currentNxProof) {
        case "NSEC":
            if (nxProof === "NSEC") {
                showAlert("success", "Proof Changed!", "The proof of non-existence was changed successfully.", divDnssecPropertiesAlert)
                return;
            }
            else {
                var iterations = $("#txtDnssecPropertiesNSEC3Iterations").val();
                var saltLength = $("#txtDnssecPropertiesNSEC3SaltLength").val();

                apiUrl = "api/zones/dnssec/properties/convertToNSEC3?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&iterations=" + iterations + "&saltLength=" + saltLength;
            }
            break;

        case "NSEC3":
            if (nxProof === "NSEC3") {
                iterations = $("#txtDnssecPropertiesNSEC3Iterations").val();
                saltLength = $("#txtDnssecPropertiesNSEC3SaltLength").val();

                if ((currentIterations == iterations) && (currentSaltLength == saltLength)) {
                    showAlert("success", "Proof Changed!", "The proof of non-existence was changed successfully.", divDnssecPropertiesAlert)
                    return;
                }
                else {
                    apiUrl = "api/zones/dnssec/properties/updateNSEC3Params?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&iterations=" + iterations + "&saltLength=" + saltLength;
                }
            } else {
                apiUrl = "api/zones/dnssec/properties/convertToNSEC?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone);
            }
            break;

        default:
            return;
    }

    if (!confirm("Are you sure you want to change the proof of non-existence options for the zone?"))
        return;

    var node = $("#optZonesClusterNode").val();

    btn.button("loading");

    HTTPRequest({
        url: apiUrl + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            btn.attr("data-nx-proof", nxProof);

            if (iterations != null)
                btn.attr("data-nsec3-iterations", iterations);

            if (saltLength != null)
                btn.attr("data-nsec3-salt-length", saltLength);

            btn.button("reset");

            var zoneHideDnssecRecords = (localStorage.getItem("zoneHideDnssecRecords") == "true");
            if (!zoneHideDnssecRecords)
                showEditZone(zone);

            showAlert("success", "Proof Changed!", "The proof of non-existence was changed successfully.", divDnssecPropertiesAlert);
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalDnssecProperties").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divDnssecPropertiesAlert
    });
}

function updateDnssecDnsKeyTtl(objBtn) {
    var btn = $(objBtn);
    var divDnssecPropertiesAlert = $("#divDnssecPropertiesAlert");
    var zone = $("#lblDnssecPropertiesZoneName").attr("data-zone");
    var ttl = $("#txtDnssecPropertiesDnsKeyTtl").val();

    var node = $("#optZonesClusterNode").val();

    btn.button("loading");

    HTTPRequest({
        url: "api/zones/dnssec/properties/updateDnsKeyTtl?token=" + sessionData.token + "&zone=" + encodeURIComponent(zone) + "&ttl=" + ttl + "&node=" + encodeURIComponent(node),
        success: function (responseJSON) {
            btn.button("reset");
            showAlert("success", "TTL Updated!", "The DNSKEY TTL was updated successfully.", divDnssecPropertiesAlert);
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalDnssecProperties").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divDnssecPropertiesAlert
    });
}
