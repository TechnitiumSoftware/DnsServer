/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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

var acmeServerDomain = null;
var acmePollTimer = null;
var acmeLoadedNode = null; //node the form was loaded from; saving is refused for any other node

$(function () {
    //ACME has its own save button; the page-wide Save Settings button doesn't apply to it
    $("a[data-toggle='tab'][href='#settingsTabPaneAcme']").on("shown.bs.tab", function () {
        $("#btnSaveSettings").hide();
        refreshAcme();
    });

    $("a[data-toggle='tab']").not("[href='#settingsTabPaneAcme']").on("shown.bs.tab", function () {
        if ($(this).closest("ul").find("#settingsTabListAcme").length > 0) {
            $("#btnSaveSettings").show();
            stopAcmePolling();
        }
    });
});

function getAcmeNode() {
    return $("#optSettingsClusterNode").val();
}

function stopAcmePolling() {
    if (acmePollTimer != null) {
        clearTimeout(acmePollTimer);
        acmePollTimer = null;
    }
}

function getAcmeDirectoryUrl() {
    var value = $("#optAcmeDirectory").val();

    if (value === "custom")
        return $("#txtAcmeCustomDirectory").val().trim();

    return value;
}

function onAcmeDirectoryChanged() {
    var value = $("#optAcmeDirectory").val();

    if (value === "custom")
        $("#divAcmeCustomDirectory").show();
    else
        $("#divAcmeCustomDirectory").hide();

    //agreement is per certificate authority; the admin must agree again for a different one
    $("#chkAcmeTermsAgreed").prop("checked", false);

    loadAcmeDirectoryInfo();
}

function onAcmeProviderChanged() {
    var provider = $("#optAcmeDns01Provider").val();

    $(".acme-provider").hide();
    $(".acme-provider-" + provider).show();
}

//shows the CA's terms of service link and whether EAB is needed, before the admin agrees
function loadAcmeDirectoryInfo() {
    var directoryUrl = getAcmeDirectoryUrl();
    var divAcmeTermsLink = $("#divAcmeTermsLink");

    if ((directoryUrl == null) || (directoryUrl === "") || !/^https:\/\//i.test(directoryUrl)) {
        divAcmeTermsLink.html("&nbsp;");
        return;
    }

    divAcmeTermsLink.text("Loading terms of service...");

    HTTPRequest({
        url: "api/settings/acme/directoryInfo?directoryUrl=" + encodeURIComponent(directoryUrl) + "&node=" + encodeURIComponent(getAcmeNode()),
        token: sessionData.token,
        success: function (responseJSON) {
            var html = "";

            var termsUrl = responseJSON.response.termsOfServiceUrl;

            if ((termsUrl != null) && /^https?:\/\//i.test(termsUrl))
                html += "Read the <a href=\"" + htmlEncode(termsUrl) + "\" target=\"_blank\" rel=\"noopener noreferrer\">terms of service</a> before agreeing.";
            else
                html += "This certificate authority does not publish a terms of service link.";

            if (responseJSON.response.externalAccountRequired) {
                html += " <b>This certificate authority requires External Account Binding (EAB) credentials.</b>";
                $("#divAcmeEab").show();
            }

            divAcmeTermsLink.html(html);
        },
        error: function () {
            divAcmeTermsLink.text("Could not reach the ACME directory URL from this server.");
        },
        invalidToken: function () {
            showPageLogin();
        }
    });
}

function formatAcmeDate(value) {
    if (value == null)
        return "never";

    return moment(value).local().format("YYYY-MM-DD HH:mm") + " (" + moment(value).fromNow() + ")";
}

function loadAcmeData(acme) {
    acmeServerDomain = acme.serverDomain;

    //status
    var status = "";

    if (acme.running)
        status += "<span class=\"label label-info\">Running</span> A certificate request is in progress; see the log below.<br />";
    else if (acme.enabled)
        status += "<span class=\"label label-success\">Enabled</span> Renews automatically " + htmlEncode(acme.renewDaysBeforeExpiry) + " days before expiry.<br />";
    else
        status += "<span class=\"label label-default\">Disabled</span><br />";

    if (acme.certificate != null) {
        var expires = moment(acme.certificate.notAfter);
        var daysLeft = expires.diff(moment(), "days");
        var expiryClass = daysLeft < 7 ? "danger" : (daysLeft <= acme.renewDaysBeforeExpiry ? "warning" : "success");

        status += "<b>Certificate:</b> " + htmlEncode(acme.certificate.dnsNames.join(", ")) + "<br />";
        status += "<b>Issuer:</b> " + htmlEncode(acme.certificate.issuer) + "<br />";
        status += "<b>Expires:</b> <span class=\"label label-" + expiryClass + "\">" + expires.local().format("YYYY-MM-DD HH:mm") + "</span> (" + daysLeft + " days)<br />";
    }
    else {
        status += "<b>Certificate:</b> none issued yet<br />";
    }

    status += "<b>Last attempt:</b> " + formatAcmeDate(acme.lastAttempt) + ", <b>last success:</b> " + formatAcmeDate(acme.lastSuccess);

    if (acme.lastError != null)
        status += "<br /><span class=\"label label-danger\">Last error</span> " + htmlEncode(acme.lastError);

    $("#divAcmeStatus").html(status);

    //settings
    $("#chkAcmeEnabled").prop("checked", acme.enabled);

    var isPresetDirectory = $("#optAcmeDirectory option").filter(function () { return this.value === acme.directoryUrl; }).length > 0;

    if (isPresetDirectory) {
        $("#optAcmeDirectory").val(acme.directoryUrl);
        $("#txtAcmeCustomDirectory").val("");
    }
    else {
        $("#optAcmeDirectory").val("custom");
        $("#txtAcmeCustomDirectory").val(acme.directoryUrl);
    }

    if ($("#optAcmeDirectory").val() === "custom")
        $("#divAcmeCustomDirectory").show();
    else
        $("#divAcmeCustomDirectory").hide();

    $("#chkAcmeTermsAgreed").prop("checked", acme.termsOfServiceAgreed);
    $("#txtAcmeEmail").val(acme.email == null ? "" : acme.email);
    $("#txtAcmeEabKeyId").val(acme.eabKeyId == null ? "" : acme.eabKeyId);
    $("#txtAcmeEabHmacKey").val("");
    $("#txtAcmeEabHmacKey").attr("placeholder", acme.eabHmacKeySet ? "(saved)" : "");

    if ((acme.eabKeyId != null) || acme.eabHmacKeySet || /zerossl|pki\.goog/i.test(acme.directoryUrl))
        $("#divAcmeEab").show();
    else
        $("#divAcmeEab").hide();

    $("#txtAcmeDomains").val(acme.domains.join("\n"));
    $("#txtAcmeDomains").attr("placeholder", acme.serverDomain);
    $("#chkAcmeUseForWebService").prop("checked", acme.useForWebService);
    $("#chkAcmeUseForDnsTls").prop("checked", acme.useForDnsTls);
    $("#optAcmeKeyType").val(acme.keyType);

    $("#optAcmeDns01Provider").val(acme.dns01Provider);
    $("#txtAcmeRfc2136Server").val(acme.rfc2136Server == null ? "" : acme.rfc2136Server);

    var tsigOptions = "<option value=\"\">None</option>";
    for (var i = 0; i < acme.tsigKeyNames.length; i++)
        tsigOptions += "<option>" + htmlEncode(acme.tsigKeyNames[i]) + "</option>";

    $("#optAcmeRfc2136TsigKey").html(tsigOptions);
    $("#optAcmeRfc2136TsigKey").val(acme.rfc2136TsigKeyName == null ? "" : acme.rfc2136TsigKeyName);

    $("#txtAcmeCloudflareToken").val("");
    $("#txtAcmeCloudflareToken").attr("placeholder", acme.cloudflareApiTokenSet ? "(saved)" : "");

    onAcmeProviderChanged();

    $("#txtAcmeRenewDays").val(acme.renewDaysBeforeExpiry);
    $("#txtAcmePropagationTimeout").val(acme.propagationTimeoutSeconds);
    $("#txtAcmePublicResolvers").val(acme.publicResolvers.join("\n"));

    //log, newest at the bottom
    var preAcmeLog = $("#preAcmeLog");
    preAcmeLog.text(acme.log.length > 0 ? acme.log.join("\n") : "No activity yet.");
    preAcmeLog.scrollTop(preAcmeLog[0].scrollHeight);

    $("#btnAcmeRequest").prop("disabled", acme.running || !acme.enabled);

    //keep the view current while a request runs
    stopAcmePolling();

    if (acme.running)
        acmePollTimer = setTimeout(function () { refreshAcme(true); }, 3000);
}

function refreshAcme(silent) {
    var divAcmeLoader = $("#divAcmeLoader");
    var divAcme = $("#divAcme");
    var node = getAcmeNode();

    if (node === "cluster") {
        stopAcmePolling();
        divAcme.hide();
        divAcmeLoader.html("<div style=\"padding: 20px;\">ACME certificates are configured per node. Select a node in the list at the top right.</div>");
        divAcmeLoader.show();
        return;
    }

    if (!silent) {
        divAcme.hide();
        divAcmeLoader.html("");
        divAcmeLoader.show();
    }

    HTTPRequest({
        url: "api/settings/acme/get?node=" + encodeURIComponent(node),
        token: sessionData.token,
        success: function (responseJSON) {
            var firstLoad = !divAcme.is(":visible") || (acmeLoadedNode !== node);

            loadAcmeData(responseJSON.response);
            acmeLoadedNode = node;

            divAcmeLoader.hide();
            divAcme.show();

            if (firstLoad)
                loadAcmeDirectoryInfo();
        },
        error: function () {
            stopAcmePolling();
        },
        invalidToken: function () {
            stopAcmePolling();
            showPageLogin();
        },
        objLoaderPlaceholder: silent ? null : divAcmeLoader
    });
}

function addAcmeServerDomain() {
    if (acmeServerDomain == null)
        return;

    var txtAcmeDomains = $("#txtAcmeDomains");
    var lines = txtAcmeDomains.val().split("\n").map(function (l) { return l.trim(); }).filter(function (l) { return l.length > 0; });

    if (lines.indexOf(acmeServerDomain) < 0)
        lines.unshift(acmeServerDomain);

    txtAcmeDomains.val(lines.join("\n"));
}

function saveAcme(objBtn) {
    if (getAcmeNode() !== acmeLoadedNode) {
        showAlert("warning", "Node Changed!", "The selected node changed since this form was loaded. The form has been reloaded for the selected node; review it and save again.");
        refreshAcme();
        return;
    }

    var enabled = $("#chkAcmeEnabled").prop("checked");
    var directoryUrl = getAcmeDirectoryUrl();
    var termsOfServiceAgreed = $("#chkAcmeTermsAgreed").prop("checked");
    var domains = $("#txtAcmeDomains").val().split("\n").map(function (l) { return l.trim(); }).filter(function (l) { return l.length > 0; });
    var provider = $("#optAcmeDns01Provider").val();

    if ((directoryUrl == null) || (directoryUrl === "")) {
        showAlert("warning", "Missing!", "Please enter the ACME directory URL.");
        $("#txtAcmeCustomDirectory").trigger("focus");
        return;
    }

    if (enabled && !termsOfServiceAgreed) {
        showAlert("warning", "Terms Of Service!", "You need to read and agree to the certificate authority's terms of service to enable ACME.");
        $("#chkAcmeTermsAgreed").trigger("focus");
        return;
    }

    if (enabled && (domains.length === 0)) {
        showAlert("warning", "Missing!", "Please enter at least one domain name.");
        $("#txtAcmeDomains").trigger("focus");
        return;
    }

    if (enabled && (provider === "Rfc2136") && ($("#txtAcmeRfc2136Server").val().trim() === "")) {
        showAlert("warning", "Missing!", "Please enter the RFC 2136 update server.");
        $("#txtAcmeRfc2136Server").trigger("focus");
        return;
    }

    if (enabled && (provider === "Cloudflare") && ($("#txtAcmeCloudflareToken").val().trim() === "") && ($("#txtAcmeCloudflareToken").attr("placeholder") === "")) {
        showAlert("warning", "Missing!", "Please enter a Cloudflare API token.");
        $("#txtAcmeCloudflareToken").trigger("focus");
        return;
    }

    var publicResolvers = $("#txtAcmePublicResolvers").val().split("\n").map(function (l) { return l.trim(); }).filter(function (l) { return l.length > 0; });

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/settings/acme/set?node=" + encodeURIComponent(getAcmeNode()),
        token: sessionData.token,
        method: "POST",
        data: "enabled=" + enabled +
            "&directoryUrl=" + encodeURIComponent(directoryUrl) +
            "&termsOfServiceAgreed=" + termsOfServiceAgreed +
            "&email=" + encodeURIComponent($("#txtAcmeEmail").val().trim()) +
            "&eabKeyId=" + encodeURIComponent($("#txtAcmeEabKeyId").val().trim()) +
            "&eabHmacKey=" + encodeURIComponent($("#txtAcmeEabHmacKey").val().trim()) +
            "&domains=" + encodeURIComponent(domains.join(",")) +
            "&keyType=" + encodeURIComponent($("#optAcmeKeyType").val()) +
            "&useForWebService=" + $("#chkAcmeUseForWebService").prop("checked") +
            "&useForDnsTls=" + $("#chkAcmeUseForDnsTls").prop("checked") +
            "&dns01Provider=" + encodeURIComponent(provider) +
            "&rfc2136Server=" + encodeURIComponent($("#txtAcmeRfc2136Server").val().trim()) +
            "&rfc2136TsigKeyName=" + encodeURIComponent($("#optAcmeRfc2136TsigKey").val()) +
            "&cloudflareApiToken=" + encodeURIComponent($("#txtAcmeCloudflareToken").val().trim()) +
            "&renewDaysBeforeExpiry=" + encodeURIComponent($("#txtAcmeRenewDays").val()) +
            "&propagationTimeoutSeconds=" + encodeURIComponent($("#txtAcmePropagationTimeout").val()) +
            "&publicResolvers=" + encodeURIComponent(publicResolvers.join(",")),
        processData: false,
        success: function (responseJSON) {
            btn.button("reset");
            loadAcmeData(responseJSON.response);
            showAlert("success", "Saved!", "ACME settings were saved successfully.");
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

function requestAcmeCertificate(objBtn) {
    if (!confirm("Request a certificate now? This contacts the certificate authority and publishes a DNS-01 TXT record. Make sure your settings are saved."))
        return;

    var btn = $(objBtn);
    btn.button("loading");

    HTTPRequest({
        url: "api/settings/acme/request?node=" + encodeURIComponent(getAcmeNode()),
        token: sessionData.token,
        method: "POST",
        success: function (responseJSON) {
            btn.button("reset");
            loadAcmeData(responseJSON.response);
            showAlert("info", "Started!", "The certificate request is running. Progress appears in the log below.");
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

function testAcmeDns01(objBtn) {
    var btn = $(objBtn);
    btn.button("loading");

    showAlert("info", "Testing...", "Publishing a test TXT record and waiting for it to appear on the public name servers. This can take a few minutes.");

    HTTPRequest({
        url: "api/settings/acme/testDns01?node=" + encodeURIComponent(getAcmeNode()),
        token: sessionData.token,
        method: "POST",
        success: function (responseJSON) {
            btn.button("reset");
            showAlert("success", "Passed!", responseJSON.response.result);
            refreshAcme(true);
        },
        error: function () {
            btn.button("reset");
            refreshAcme(true);
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        }
    });
}
