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

var sessionData = null;
var localGroups = null;
var otpTimerHandle = null;

$(function () {
    var hash = window.location.hash;
    if (hash.length > 0)
        hash = "?" + hash.substr(1);

    var urlParams = new URLSearchParams(hash);
    window.history.replaceState(null, '', window.location.protocol + "//" + window.location.host + window.location.pathname);

    var errorMessage = urlParams.get("error");
    if (errorMessage != null) {
        showPageLogin();
        showAlert("danger", "Error!", errorMessage);
    }
    else {
        var token = getCookie("token");
        if (token != null)
            setCookie("token", "", 0); //delete cookie immediately
        else
            token = localStorage.getItem("token");

        if (token == null) {
            showPageLogin();
            login("admin", "admin");
        }
        else {
            HTTPRequest({
                url: "api/user/session/get",
                token: token,
                success: function (responseJSON) {
                    sessionData = responseJSON;
                    localStorage.setItem("token", sessionData.token);

                    $("#mnuUserDisplayName").text(sessionData.displayName);
                    document.title = sessionData.info.dnsServerDomain + " - " + "Technitium DNS Server v" + sessionData.info.version;
                    $("#lblAboutVersion").text(sessionData.info.version);
                    $("#lblAboutUptime").text(moment(sessionData.info.uptimestamp).local().format("lll") + " (" + moment(sessionData.info.uptimestamp).fromNow() + ")");
                    $("#lblDnsServerDomain").text(" - " + sessionData.info.dnsServerDomain);
                    $("#chkUseSoaSerialDateScheme").prop("checked", sessionData.info.useSoaSerialDateScheme);
                    $("#chkDnssecValidation").prop("checked", sessionData.info.dnssecValidation);

                    showPageMain();
                },
                error: function () {
                    showPageLogin();
                }
            });
        }
    }

    $("#optGroupDetailsUserList").on("change", function () {
        var selectedUser = $("#optGroupDetailsUserList").val();

        switch (selectedUser) {
            case "blank":
                break;

            case "none":
                $("#txtGroupDetailsMembers").val("");
                break;

            default:
                var existingUsers = $("#txtGroupDetailsMembers").val();
                var existingUsersArray = existingUsers.split("\n");
                var found = false;

                for (var i = 0; i < existingUsersArray.length; i++) {
                    if (existingUsersArray[i] === selectedUser) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    if ((existingUsers.length > 0) && !existingUsers.endsWith("\n"))
                        existingUsers += "\n";

                    existingUsers += selectedUser + "\n";
                    $("#txtGroupDetailsMembers").val(existingUsers);
                }
                break;
        }
    });

    $("#optUserDetailsGroupList").on("change", function () {
        var selectedGroup = $("#optUserDetailsGroupList").val();

        switch (selectedGroup) {
            case "blank":
                break;

            case "none":
                $("#txtUserDetailsMemberOf").val("");
                break;

            default:
                var existingGroups = $("#txtUserDetailsMemberOf").val();
                var existingGroupsArray = existingGroups.split("\n");
                var found = false;

                for (var i = 0; i < existingGroupsArray.length; i++) {
                    if (existingGroupsArray[i] === selectedGroup) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    if ((existingGroups.length > 0) && !existingGroups.endsWith("\n"))
                        existingGroups += "\n";

                    existingGroups += selectedGroup + "\n";
                    $("#txtUserDetailsMemberOf").val(existingGroups);
                }
                break;
        }
    });

    $("#optEditPermissionsUserList").on("change", function () {
        var selectedUser = $("#optEditPermissionsUserList").val();

        switch (selectedUser) {
            case "blank":
                break;

            case "none":
                $("#tbodyEditPermissionsUser").html("");
                break;

            default:
                var data = serializeTableData($("#tableEditPermissionsUser"), 4);
                var parts = data.split("|");
                var found = false;

                for (var i = 0; i < parts.length; i += 4) {
                    if (parts[i] === selectedUser) {
                        found = true;
                        break;
                    }
                }

                if (!found)
                    addEditPermissionUserRow(null, selectedUser, false, false, false);

                break;
        }
    });

    $("#optEditPermissionsGroupList").on("change", function () {
        var selectedGroup = $("#optEditPermissionsGroupList").val();

        switch (selectedGroup) {
            case "blank":
                break;

            case "none":
                $("#tbodyEditPermissionsGroup").html("");
                break;

            default:
                var data = serializeTableData($("#tableEditPermissionsGroup"), 4);
                var parts = data.split("|");
                var found = false;

                for (var i = 0; i < parts.length; i += 4) {
                    if (parts[i] === selectedGroup) {
                        found = true;
                        break;
                    }
                }

                if (!found)
                    addEditPermissionGroupRow(null, selectedGroup, false, false, false);

                break;
        }
    });
});

function login(username, password) {
    if (otpTimerHandle != null)
        clearTimeout(otpTimerHandle);

    const OTP_TIMEOUT_INTERVAL = 30000;

    var autoLogin = false;

    if (username == null) {
        username = $("#txtUser").val().toLowerCase();
        password = $("#txtPass").val();
    }
    else {
        autoLogin = true;
    }

    if ((username === null) || (username === "")) {
        showAlert("warning", "Missing!", "Please enter an username.");
        $("#txtUser").trigger("focus");
        return;
    }

    if ((password === null) || (password === "")) {
        showAlert("warning", "Missing!", "Please enter a password.");
        $("#txtPass").trigger("focus");
        return;
    }

    var totp = $("#txt2FATOTP").val();

    if ($("#div2FAOTP").is(":visible")) {
        if ((totp == null) || (totp.length != 6)) {
            showAlert("warning", "Missing!", "Please enter the 6-digit OTP that you see in your authenticator app.");
            $("#txt2FATOTP").trigger("focus");
            otpTimerHandle = setTimeout(showPageLogin, OTP_TIMEOUT_INTERVAL);
            return;
        }
    }

    var btn = $("#btnLogin").button("loading");

    HTTPRequest({
        url: "api/user/login",
        method: "POST",
        data: "user=" + encodeURIComponent(username) + "&pass=" + encodeURIComponent(password) + "&totp=" + encodeURIComponent(totp) + "&includeInfo=true",
        procecssData: false,
        success: function (responseJSON) {
            sessionData = responseJSON;
            localStorage.setItem("token", sessionData.token);

            $("#mnuUserDisplayName").text(sessionData.displayName);
            document.title = sessionData.info.dnsServerDomain + " - " + "Technitium DNS Server v" + sessionData.info.version;
            $("#lblAboutVersion").text(sessionData.info.version);
            $("#lblAboutUptime").text(moment(sessionData.info.uptimestamp).local().format("lll") + " (" + moment(sessionData.info.uptimestamp).fromNow() + ")");
            $("#lblDnsServerDomain").text(" - " + sessionData.info.dnsServerDomain);

            showPageMain();

            if (!sessionData.totpEnabled && (username === "admin") && (password === "admin"))
                showChangePasswordModal(password);
        },
        error: function () {
            btn.button("reset");

            if ($("#div2FAOTP").is(":visible")) {
                $("#txt2FATOTP").val("");
                $("#txt2FATOTP").trigger("focus");
                otpTimerHandle = setTimeout(showPageLogin, OTP_TIMEOUT_INTERVAL);
            }
            else {
                $("#txtUser").trigger("focus");
            }

            if (autoLogin)
                hideAlert();
        },
        twoFactorAuthRequired: function () {
            btn.button("reset");

            if (autoLogin) {
                $("#txtUser").trigger("focus");
            }
            else {
                $("#txtPass").prop("disabled", true);
                $("#div2FAOTP").show();
                $("#txt2FATOTP").trigger("focus");
                otpTimerHandle = setTimeout(showPageLogin, OTP_TIMEOUT_INTERVAL);
            }
        }
    });
}

function logout() {
    HTTPRequest({
        url: "api/user/logout",
        token: sessionData.token,
        success: function (responseJSON) {
            sessionData = null;
            showPageLogin();
        },
        error: function () {
            sessionData = null;
            showPageLogin();
        }
    });
}

function showCreateMyApiTokenModal() {
    $("#divCreateApiTokenAlert").html("");
    $("#txtCreateApiTokenUsername").val(sessionData.username);
    $("#txtCreateApiTokenName").val("");

    $("#txtCreateApiTokenUsername").show();
    $("#optCreateApiTokenUsername").hide();

    $("#divCreateApiTokenLoader").hide();
    $("#divCreateApiTokenForm").show();
    $("#divCreateApiTokenOutput").hide();

    var btnCreateApiToken = $("#btnCreateApiToken");
    btnCreateApiToken.attr("onclick", "createMyApiToken(this); return false;");
    btnCreateApiToken.show();

    $("#modalCreateApiToken").modal("show");

    setTimeout(function () {
        $("#txtCreateApiTokenName").trigger("focus");
    }, 1000);
}

function createMyApiToken(objBtn) {
    var btn = $(objBtn);

    var divCreateApiTokenAlert = $("#divCreateApiTokenAlert");

    var tokenName = $("#txtCreateApiTokenName").val();
    if (tokenName === "") {
        showAlert("warning", "Missing!", "Please enter a token name.", divCreateApiTokenAlert);
        $("#txtCreateApiTokenName").trigger("focus");
        return;
    }

    btn.button("loading");

    HTTPRequest({
        url: "api/user/createToken",
        token: sessionData.token,
        method: "POST",
        data: "tokenName=" + encodeURIComponent(tokenName),
        processData: false,
        success: function (responseJSON) {
            btn.button("reset");
            btn.hide();

            $("#lblCreateApiTokenOutputUsername").text(responseJSON.username);
            $("#lblCreateApiTokenOutputTokenName").text(responseJSON.tokenName);
            $("#lblCreateApiTokenOutputToken").text(responseJSON.token);

            $("#divCreateApiTokenForm").hide();
            $("#divCreateApiTokenOutput").show();

            showAlert("success", "Token Created!", "API token was created successfully.", divCreateApiTokenAlert);
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalCreateApiToken").hide("");
            showPageLogin();
        },
        objAlertPlaceholder: divCreateApiTokenAlert
    });
}

function showChangePasswordModal(currentPassword) {
    $("#titleChangePassword").text("Change Password");

    hideAlert($("#divChangePasswordAlert"));
    $("#txtChangePasswordUsername").val(sessionData.username);

    var txtChangePasswordCurrentPassword = $("#txtChangePasswordCurrentPassword");

    if (currentPassword == null) {
        txtChangePasswordCurrentPassword.val("");
        txtChangePasswordCurrentPassword.prop("disabled", false);
    }
    else {
        txtChangePasswordCurrentPassword.val(currentPassword);
        txtChangePasswordCurrentPassword.prop("disabled", true);
    }

    $("#divChangePasswordCurrentPassword").show();

    $("#txtChangePasswordNewPassword").val("");
    $("#txtChangePasswordConfirmPassword").val("");

    $("#txtChangePassword2FATOTP").val("");

    if (sessionData.totpEnabled)
        $("#divChangePassword2FATOTP").show();
    else
        $("#divChangePassword2FATOTP").hide();

    var btnChangePassword = $("#btnChangePassword");
    btnChangePassword.text("Change");
    btnChangePassword.attr("onclick", "changePassword(this); return false;");
    btnChangePassword.show();

    $("#modalChangePassword").modal("show");

    setTimeout(function () {
        if (currentPassword == null)
            $("#txtChangePasswordCurrentPassword").trigger("focus");
        else
            $("#txtChangePasswordNewPassword").trigger("focus");
    }, 1000);
}

function changePassword(objBtn) {
    var btn = $(objBtn);

    var divChangePasswordAlert = $("#divChangePasswordAlert");

    var password = $("#txtChangePasswordCurrentPassword").val();
    var newPassword = $("#txtChangePasswordNewPassword").val();
    var confirmPassword = $("#txtChangePasswordConfirmPassword").val();
    var totp = $("#txtChangePassword2FATOTP").val();

    if ((password === null) || (password === "")) {
        showAlert("warning", "Missing!", "Please enter the current password.", divChangePasswordAlert);
        $("#txtChangePasswordCurrentPassword").trigger("focus");
        return;
    }

    if ((newPassword === null) || (newPassword === "")) {
        showAlert("warning", "Missing!", "Please enter new password.", divChangePasswordAlert);
        $("#txtChangePasswordNewPassword").trigger("focus");
        return;
    }

    if ((confirmPassword === null) || (confirmPassword === "")) {
        showAlert("warning", "Missing!", "Please enter confirm password.", divChangePasswordAlert);
        $("#txtChangePasswordConfirmPassword").trigger("focus");
        return;
    }

    if (newPassword !== confirmPassword) {
        showAlert("warning", "Mismatch!", "Passwords do not match. Please try again.", divChangePasswordAlert);
        $("#txtChangePasswordNewPassword").trigger("focus");
        return;
    }

    if (sessionData.totpEnabled) {
        if ((totp == null) || (totp.length != 6)) {
            showAlert("warning", "Missing!", "Please enter the 6-digit OTP that you see in your authenticator app.", divChangePasswordAlert);
            $("#txtChangePassword2FATOTP").trigger("focus");
            return;
        }
    }

    btn.button("loading");

    HTTPRequest({
        url: "api/user/changePassword",
        token: sessionData.token,
        method: "POST",
        data: "pass=" + encodeURIComponent(password) + "&newPass=" + encodeURIComponent(newPassword) + "&totp=" + encodeURIComponent(totp),
        processData: false,
        success: function (responseJSON) {
            $("#modalChangePassword").modal("hide");
            $("#txtChangePasswordCurrentPassword").val("");
            $("#txtChangePasswordNewPassword").val("");
            $("#txtChangePasswordConfirmPassword").val("");
            $("#txtChangePassword2FATOTP").val("");
            btn.button("reset");

            showAlert("success", "Password Changed!", "Password was changed successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalChangePassword").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divChangePasswordAlert
    });
}

function showConfigure2FAModal() {
    var divConfigure2FAAlert = $("#divConfigure2FAAlert");
    var divConfigure2FALoader = $("#divConfigure2FALoader");
    var divConfigure2FAViewer = $("#divConfigure2FAViewer");
    var btnEnable2FA = $("#btnEnable2FA");
    var btnDisable2FA = $("#btnDisable2FA");

    divConfigure2FALoader.show();
    divConfigure2FAViewer.hide();

    btnEnable2FA.hide();
    btnDisable2FA.hide();

    var modalConfigure2FA = $("#modalConfigure2FA");
    modalConfigure2FA.modal("show");

    HTTPRequest({
        url: "api/user/2fa/init",
        token: sessionData.token,
        success: function (responseJSON) {
            $("#txtConfigure2FAUsername").val(sessionData.username);
            $("#lblConfigure2FAStatus").text(responseJSON.response.totpEnabled ? "Enabled" : "Disabled");

            if (responseJSON.response.totpEnabled) {
                $("#divConfigure2FAInitialize").hide();

                divConfigure2FALoader.hide();
                divConfigure2FAViewer.show();

                btnDisable2FA.show();
            }
            else {
                var secret = "";

                for (var i = 0; i < responseJSON.response.secret.length; i++) {
                    if ((i > 0) && (i % 4) == 0)
                        secret += " ";

                    secret += responseJSON.response.secret.substring(i, i + 1);
                }

                $("#lblConfigure2FAQRCode").html("<img src=\"data:image/png;base64, " + responseJSON.response.qrCodePngImage + "\" />");
                $("#lblConfigure2FASecret").text(secret);
                $("#txtConfigure2FATOTP").val("");

                $("#divConfigure2FAInitialize").show();

                divConfigure2FALoader.hide();
                divConfigure2FAViewer.show();

                btnEnable2FA.show();

                setTimeout(function () {
                    $("#txtConfigure2FATOTP").trigger("focus");
                }, 1000);
            }
        },
        error: function () {
            divConfigure2FALoader.hide();
        },
        invalidToken: function () {
            modalConfigure2FA.modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divConfigure2FAAlert,
        objLoaderPlaceholder: divConfigure2FALoader
    });
}

function enable2FA(objBtn) {
    var btn = $(objBtn);

    var divConfigure2FAAlert = $("#divConfigure2FAAlert");
    var totp = $("#txtConfigure2FATOTP").val();

    if ((totp == null) || (totp.length != 6)) {
        showAlert("warning", "Missing!", "Please enter the 6-digit OTP that you see in your authenticator app.", divConfigure2FAAlert);
        $("#txtConfigure2FATOTP").trigger("focus");
        return;
    }

    btn.button("loading");

    HTTPRequest({
        url: "api/user/2fa/enable",
        token: sessionData.token,
        method: "POST",
        data: "totp=" + encodeURIComponent(totp),
        processData: false,
        success: function (responseJSON) {
            sessionData.totpEnabled = true;

            $("#modalConfigure2FA").modal("hide");
            btn.button("reset");

            showAlert("success", "2FA Enabled!", "Two-factor authentication (2FA) was enabled successfully.");
        },
        error: function () {
            btn.button("reset");
            $("#txtConfigure2FATOTP").val("");
            $("#txtConfigure2FATOTP").trigger("focus");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalConfigure2FA").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divConfigure2FAAlert
    });
}

function disable2FA(objBtn) {
    if (!confirm("Are you sure you want to disable Two-factor authentication (2FA) ?"))
        return;

    var btn = $(objBtn);

    var divConfigure2FAAlert = $("#divConfigure2FAAlert");

    btn.button("loading");

    HTTPRequest({
        url: "api/user/2fa/disable",
        token: sessionData.token,
        success: function (responseJSON) {
            sessionData.totpEnabled = false;

            $("#modalConfigure2FA").modal("hide");
            btn.button("reset");

            showAlert("success", "2FA Disabled!", "Two-factor authentication (2FA) was disabled successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalConfigure2FA").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divConfigure2FAAlert
    });
}

function showMyProfileModal() {
    var divMyProfileAlert = $("#divMyProfileAlert");
    var divMyProfileLoader = $("#divMyProfileLoader");
    var divMyProfileViewer = $("#divMyProfileViewer");

    divMyProfileLoader.show();
    divMyProfileViewer.hide();

    var modalMyProfile = $("#modalMyProfile");
    modalMyProfile.modal("show");

    HTTPRequest({
        url: "api/user/profile/get",
        token: sessionData.token,
        success: function (responseJSON) {
            sessionData.displayName = responseJSON.response.displayName;
            sessionData.username = responseJSON.response.username;
            sessionData.totpEnabled = responseJSON.response.totpEnabled;

            $("#mnuUserDisplayName").text(sessionData.displayName);

            $("#txtMyProfileDisplayName").prop("disabled", responseJSON.response.isSsoUser);
            $("#txtMyProfileDisplayName").val(responseJSON.response.displayName);
            $("#txtMyProfileUsername").val(responseJSON.response.username);

            if (responseJSON.response.isSsoUser) {
                $("#lblMyProfileUserType").text("Remote/SSO");
                $("#lblMyProfile2FAStatus").text("SSO Managed");
            }
            else {
                $("#lblMyProfileUserType").text("Local");
                $("#lblMyProfile2FAStatus").text(responseJSON.response.totpEnabled ? "Enabled" : "Disabled");
            }

            $("#txtMyProfileSessionTimeout").val(responseJSON.response.sessionTimeoutSeconds);

            {
                var groupHtmlRows = "";

                for (var i = 0; i < responseJSON.response.memberOfGroups.length; i++) {
                    groupHtmlRows += "<tr><td>" + htmlEncode(responseJSON.response.memberOfGroups[i]) + "</td></tr>";
                }

                $("#tbodyMyProfileMemberOf").html(groupHtmlRows);
                $("#tfootMyProfileMemberOf").html("Total Groups: " + responseJSON.response.memberOfGroups.length);
            }

            {
                var sessionHtmlRows = "";

                for (var i = 0; i < responseJSON.response.sessions.length; i++) {
                    var session;

                    if (responseJSON.response.sessions[i].tokenName == null)
                        session = htmlEncode("[" + responseJSON.response.sessions[i].partialToken + "]");
                    else
                        session = htmlEncode(responseJSON.response.sessions[i].tokenName) + "<br />[" + htmlEncode(responseJSON.response.sessions[i].partialToken) + "]";

                    if (responseJSON.response.sessions[i].isCurrentSession)
                        session += "<br />(current)";

                    switch (responseJSON.response.sessions[i].type) {
                        case "Standard":
                            session += "<br /><span class=\"label label-default\">Standard</span>";
                            break;

                        case "ApiToken":
                            session += "<br /><span class=\"label label-info\">API Token</span>";
                            break;

                        case "ClusterApiToken":
                            session += "<br /><span class=\"label label-primary\">Cluster API Token</span>";
                            break;

                        default:
                            session += "<br /><span class=\"label label-warning\">Unknown</span>";
                            break;
                    }

                    sessionHtmlRows += "<tr id=\"trMyProfileActiveSessions" + i + "\"><td style=\"min-width: 155px; word-wrap: anywhere;\">" + session + "</td><td>" +
                        htmlEncode(moment(responseJSON.response.sessions[i].lastSeen).local().format("YYYY-MM-DD HH:mm:ss")) + "<br /><span style=\"font-size: 12px\">" + htmlEncode("(" + moment(responseJSON.response.sessions[i].lastSeen).fromNow() + ")") + "</span></td><td>" +
                        htmlEncode(responseJSON.response.sessions[i].lastSeenRemoteAddress) + "</td><td style=\"word-wrap: anywhere;\">" +
                        htmlEncode(responseJSON.response.sessions[i].lastSeenUserAgent);

                    sessionHtmlRows += "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnMyProfileActiveSessionRowOption" + i + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
                    sessionHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" data-session-type=\"" + responseJSON.response.sessions[i].type + "\" data-partial-token=\"" + responseJSON.response.sessions[i].partialToken + "\" onclick=\"deleteMySession(this); return false;\">Delete Session</a></li>";
                    sessionHtmlRows += "</ul></div></td></tr>";
                }

                $("#tbodyMyProfileActiveSessions").html(sessionHtmlRows);
                $("#tfootMyProfileActiveSessions").html("Total Sessions: " + responseJSON.response.sessions.length);
            }

            divMyProfileLoader.hide();
            divMyProfileViewer.show();

            setTimeout(function () {
                $("#txtMyProfileDisplayName").trigger("focus");
            }, 1000);
        },
        error: function () {
            divMyProfileLoader.hide();
        },
        invalidToken: function () {
            modalMyProfile.modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divMyProfileAlert,
        objLoaderPlaceholder: divMyProfileLoader
    });
}

function saveMyProfile(objBtn) {
    var btn = $(objBtn);
    var divMyProfileAlert = $("#divMyProfileAlert");

    var sessionTimeoutSeconds = $("#txtMyProfileSessionTimeout").val();
    if (sessionTimeoutSeconds === "")
        sessionTimeoutSeconds = 1800;

    var params = "sessionTimeoutSeconds=" + encodeURIComponent(sessionTimeoutSeconds);

    if (!$("#txtMyProfileDisplayName").prop("disabled")) {
        var displayName = $("#txtMyProfileDisplayName").val();
        params += "&displayName=" + encodeURIComponent(displayName);
    }

    btn.button("loading");

    HTTPRequest({
        url: "api/user/profile/set?" + params,
        token: sessionData.token,
        success: function (responseJSON) {
            sessionData.displayName = responseJSON.response.displayName;
            $("#mnuUserDisplayName").text(sessionData.displayName);

            btn.button("reset");
            $("#modalMyProfile").modal("hide");

            showAlert("success", "Profile Saved!", "User profile was saved successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalMyProfile").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divMyProfileAlert
    });
}

function deleteMySession(objMenuItem) {
    var divMyProfileAlert = $("#divMyProfileAlert");
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var sessionType = mnuItem.attr("data-session-type");
    var partialToken = mnuItem.attr("data-partial-token");

    if (!confirm("Are you sure you want to delete the session [" + partialToken + "] ?"))
        return;

    var apiUrl = "api/user/session/delete?partialToken=" + encodeURIComponent(partialToken);

    if (sessionType == "ApiToken")
        apiUrl += "&node=" + encodeURIComponent(getPrimaryClusterNodeName());

    var btn = $("#btnMyProfileActiveSessionRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<img src='/img/loader-small.gif'/>");

    HTTPRequest({
        url: apiUrl,
        token: sessionData.token,
        success: function (responseJSON) {
            $("#trMyProfileActiveSessions" + id).remove();

            var totalSessions = $('#tableMyProfileActiveSessions >tbody >tr').length;
            $("#tfootMyProfileActiveSessions").html("Total Sessions: " + totalSessions);

            showAlert("success", "Session Deleted!", "The user session was deleted successfully.", divMyProfileAlert);
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            $("#modalMyProfile").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divMyProfileAlert
    });
}

function refreshAdminTab() {
    if ($("#adminTabListSessions").hasClass("active"))
        refreshAdminSessions();
    else if ($("#adminTabListUsers").hasClass("active"))
        refreshAdminUsers();
    else if ($("#adminTabListGroups").hasClass("active"))
        refreshAdminGroups();
    else if ($("#adminTabListPermissions").hasClass("active"))
        refreshAdminPermissions();
    else if ($("#adminTabListSso").hasClass("active"))
        refreshAdminSsoConfig();
    else if ($("#adminTabListCluster").hasClass("active"))
        refreshAdminCluster();
    else
        refreshAdminSessions();
}

function refreshAdminSessions() {
    var divAdminSessionsLoader = $("#divAdminSessionsLoader");
    var divAdminSessionsView = $("#divAdminSessionsView");

    var node = $("#optAdminSessionsClusterNode").val();

    divAdminSessionsLoader.show();
    divAdminSessionsView.hide();

    HTTPRequest({
        url: "api/admin/sessions/list?node=" + encodeURIComponent(node),
        token: sessionData.token,
        success: function (responseJSON) {
            var tableHtmlRows = "";

            for (var i = 0; i < responseJSON.response.sessions.length; i++) {
                var session;

                if (responseJSON.response.sessions[i].tokenName == null)
                    session = "[" + htmlEncode(responseJSON.response.sessions[i].partialToken) + "]";
                else
                    session = htmlEncode(responseJSON.response.sessions[i].tokenName) + "<br />[" + htmlEncode(responseJSON.response.sessions[i].partialToken) + "]";

                if (responseJSON.response.sessions[i].isCurrentSession)
                    session += "<br />(current)";

                switch (responseJSON.response.sessions[i].type) {
                    case "Standard":
                        session += "<br /><span class=\"label label-default\">Standard</span>";
                        break;

                    case "ApiToken":
                        session += "<br /><span class=\"label label-info\">API Token</span>";
                        break;

                    case "ClusterApiToken":
                        session += "<br /><span class=\"label label-primary\">Cluster API Token</span>";
                        break;

                    default:
                        session += "<br /><span class=\"label label-warning\">Unknown</span>";
                        break;
                }

                tableHtmlRows += "<tr id=\"trAdminSessions" + i + "\"><td><a href=\"#\" data-username=\"" + htmlEncode(responseJSON.response.sessions[i].username) + "\" onclick=\"showUserDetailsModal(this); return false;\">" + htmlEncode(responseJSON.response.sessions[i].username) + "</a></td><td style=\"min-width: 155px; word-wrap: anywhere;\">" +
                    session + "</td><td>" +
                    htmlEncode(moment(responseJSON.response.sessions[i].lastSeen).local().format("YYYY-MM-DD HH:mm:ss")) + "<br /><span style=\"font-size: 12px\">" + htmlEncode("(" + moment(responseJSON.response.sessions[i].lastSeen).fromNow() + ")") + "</span></td><td>" +
                    htmlEncode(responseJSON.response.sessions[i].lastSeenRemoteAddress) + "</td><td style=\"word-wrap: anywhere;\">" +
                    htmlEncode(responseJSON.response.sessions[i].lastSeenUserAgent);

                tableHtmlRows += "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnAdminSessionRowOption" + i + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
                tableHtmlRows += "<li><a href=\"#\" data-username=\"" + htmlEncode(responseJSON.response.sessions[i].username) + "\" onclick=\"showUserDetailsModal(this); return false;\">View User Details</a></li>";
                tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" data-session-type=\"" + responseJSON.response.sessions[i].type + "\" data-partial-token=\"" + responseJSON.response.sessions[i].partialToken + "\" onclick=\"deleteAdminSession(this); return false;\">Delete Session</a></li>";
                tableHtmlRows += "</ul></div></td></tr>";
            }

            var primaryNodeName = getPrimaryClusterNodeName();

            if ((primaryNodeName == "") || (primaryNodeName == responseJSON.server))
                $("#btnAdminSessionsCreateToken").show();
            else
                $("#btnAdminSessionsCreateToken").hide();

            $("#tbodyAdminSessions").html(tableHtmlRows);
            $("#tfootAdminSessions").html("Total Sessions: " + responseJSON.response.sessions.length);

            divAdminSessionsLoader.hide();
            divAdminSessionsView.show();
        },
        error: function () {
            divAdminSessionsLoader.hide();
            divAdminSessionsView.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divAdminSessionsLoader
    });
}

function showCreateApiTokenModal() {
    var divCreateApiTokenAlert = $("#divCreateApiTokenAlert");
    var divCreateApiTokenLoader = $("#divCreateApiTokenLoader");
    var divCreateApiTokenForm = $("#divCreateApiTokenForm");
    var divCreateApiTokenOutput = $("#divCreateApiTokenOutput");

    divCreateApiTokenLoader.show();
    divCreateApiTokenForm.hide();
    divCreateApiTokenOutput.hide();

    var btnCreateApiToken = $("#btnCreateApiToken");
    btnCreateApiToken.attr("onclick", "createApiToken(this); return false;");
    btnCreateApiToken.show();

    var modalCreateApiToken = $("#modalCreateApiToken");
    modalCreateApiToken.modal("show");

    HTTPRequest({
        url: "api/admin/users/list",
        token: sessionData.token,
        success: function (responseJSON) {
            var userListHtml = "";

            for (var i = 0; i < responseJSON.response.users.length; i++) {
                userListHtml += "<option>" + htmlEncode(responseJSON.response.users[i].username) + "</option>";
            }

            $("#optCreateApiTokenUsername").html(userListHtml);

            $("#optCreateApiTokenUsername").show();
            $("#txtCreateApiTokenUsername").hide();
            $("#txtCreateApiTokenName").val("");

            divCreateApiTokenLoader.hide();
            divCreateApiTokenForm.show();

            setTimeout(function () {
                $("#optCreateApiTokenUsername").trigger("focus");
            }, 1000);
        },
        error: function () {
            divCreateApiTokenLoader.hide();
        },
        invalidToken: function () {
            modalCreateApiToken.modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divCreateApiTokenAlert,
        objLoaderPlaceholder: divCreateApiTokenLoader
    });
}

function createApiToken(objBtn) {
    var btn = $(objBtn);

    var divCreateApiTokenAlert = $("#divCreateApiTokenAlert");

    var user = $("#optCreateApiTokenUsername").val();
    var tokenName = $("#txtCreateApiTokenName").val();

    if (user === "") {
        showAlert("warning", "Missing!", "Please select a username.", divCreateApiTokenAlert);
        $("#optCreateApiTokenUsername").trigger("focus");
        return;
    }

    if (tokenName === "") {
        showAlert("warning", "Missing!", "Please enter a token name.", divCreateApiTokenAlert);
        $("#txtCreateApiTokenName").trigger("focus");
        return;
    }

    btn.button("loading");

    HTTPRequest({
        url: "api/admin/sessions/createToken?user=" + encodeURIComponent(user) + "&tokenName=" + encodeURIComponent(tokenName),
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");
            btn.hide();

            $("#lblCreateApiTokenOutputUsername").text(responseJSON.response.username);
            $("#lblCreateApiTokenOutputTokenName").text(responseJSON.response.tokenName);
            $("#lblCreateApiTokenOutputToken").text(responseJSON.response.token);

            $("#divCreateApiTokenForm").hide();
            $("#divCreateApiTokenOutput").show();

            showAlert("success", "Token Created!", "API token was created successfully.", divCreateApiTokenAlert);

            refreshAdminSessions();
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalCreateApiToken").hide("");
            showPageLogin();
        },
        objAlertPlaceholder: divCreateApiTokenAlert
    });
}

function deleteAdminSession(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var sessionType = mnuItem.attr("data-session-type");
    var partialToken = mnuItem.attr("data-partial-token");

    if (!confirm("Are you sure you want to delete the session [" + partialToken + "] ?"))
        return;

    var apiUrl = "api/admin/sessions/delete?partialToken=" + encodeURIComponent(partialToken);

    if (sessionType == "ApiToken")
        apiUrl += "&node=" + encodeURIComponent(getPrimaryClusterNodeName());
    else
        apiUrl += "&node=" + encodeURIComponent($("#optAdminSessionsClusterNode").val());

    var btn = $("#btnAdminSessionRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<img src='/img/loader-small.gif'/>");

    HTTPRequest({
        url: apiUrl,
        token: sessionData.token,
        success: function (responseJSON) {
            $("#trAdminSessions" + id).remove();

            var totalSessions = $('#tableAdminSessions >tbody >tr').length;
            $("#tfootAdminSessions").html("Total Sessions: " + totalSessions);

            showAlert("success", "Session Deleted!", "The user session was deleted successfully.");
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

function refreshAdminUsers() {
    var divAdminUsersLoader = $("#divAdminUsersLoader");
    var divAdminUsersView = $("#divAdminUsersView");

    divAdminUsersLoader.show();
    divAdminUsersView.hide();

    HTTPRequest({
        url: "api/admin/users/list",
        token: sessionData.token,
        success: function (responseJSON) {
            var tableHtmlRows = "";

            for (var i = 0; i < responseJSON.response.users.length; i++) {
                tableHtmlRows += getAdminUsersRowHtml(i, responseJSON.response.users[i]);
            }

            $("#tbodyAdminUsers").html(tableHtmlRows);
            $("#tfootAdminUsers").html("Total Users: " + responseJSON.response.users.length);

            divAdminUsersLoader.hide();
            divAdminUsersView.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divAdminUsersLoader
    });
}

function getAdminUsersRowHtml(id, user) {
    var userType;
    var totpStatus;

    if (user.isSsoUser) {
        userType = "Remote/SSO";
        totpStatus = "<span class=\"label label-info\">SSO Managed</span>"
    }
    else {
        userType = "Local";

        if (user.totpEnabled)
            totpStatus = "<span class=\"label label-success\">Enabled</span>";
        else
            totpStatus = "<span class=\"label label-default\">Disabled</span>";
    }

    var status;
    if (user.disabled)
        status = "<span class=\"label label-default\">Disabled</span>";
    else
        status = "<span class=\"label label-success\">Enabled</span>";

    var tableHtmlRows = "<tr id=\"trAdminUsers" + id + "\"><td style=\"word-wrap: anywhere;\"><a href=\"#\" data-id=\"" + id + "\" data-username=\"" + htmlEncode(user.username) + "\" onclick=\"showUserDetailsModal(this); return false;\">" + htmlEncode(user.username) + "</a></td><td style=\"word-wrap: anywhere;\">" +
        htmlEncode(user.displayName) + "</td><td>" +
        userType + "</td><td>" +
        totpStatus + "</td><td>" +
        status + "</td><td>" +
        htmlEncode(moment(user.recentSessionLoggedOn).local().format("YYYY-MM-DD HH:mm:ss")) + " from " + htmlEncode(user.recentSessionRemoteAddress) + "</td><td>" +
        htmlEncode(moment(user.previousSessionLoggedOn).local().format("YYYY-MM-DD HH:mm:ss")) + " from " + htmlEncode(user.previousSessionRemoteAddress);

    tableHtmlRows += "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnAdminUserRowOption" + id + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
    tableHtmlRows += "<li><a href=\"#\" data-id=\"" + id + "\" data-username=\"" + htmlEncode(user.username) + "\" onclick=\"showUserDetailsModal(this); return false;\">View Details</a></li>";
    tableHtmlRows += "<li id=\"mnuAdminUserRowEnable" + id + "\"" + (user.disabled ? "" : " style=\"display: none;\"") + "><a href=\"#\" data-id=\"" + id + "\" data-username=\"" + htmlEncode(user.username) + "\" onclick=\"enableUser(this); return false;\">Enable</a></li>";
    tableHtmlRows += "<li id=\"mnuAdminUserRowDisable" + id + "\"" + (!user.disabled ? "" : " style=\"display: none;\"") + "><a href=\"#\" data-id=\"" + id + "\" data-username=\"" + htmlEncode(user.username) + "\" onclick=\"disableUser(this); return false;\">Disable</a></li>";

    if (!user.isSsoUser) {
        tableHtmlRows += "<li><a href=\"#\" data-id=\"" + id + "\" data-username=\"" + htmlEncode(user.username) + "\" onclick=\"showResetUserPasswordModal(this); return false;\">Reset Password</a></li>";

        if (user.totpEnabled)
            tableHtmlRows += "<li><a href=\"#\" data-id=\"" + id + "\" data-username=\"" + htmlEncode(user.username) + "\" onclick=\"adminDisable2FA(this); return false;\">Disable 2FA</a></li>";
    }

    tableHtmlRows += "<li role=\"separator\" class=\"divider\"></li>";
    tableHtmlRows += "<li><a href=\"#\" data-id=\"" + id + "\" data-username=\"" + htmlEncode(user.username) + "\" onclick=\"deleteUser(this); return false;\">Delete User</a></li>";
    tableHtmlRows += "</ul></div></td></tr>";

    return tableHtmlRows;
}

function showAddUserModal() {
    $("#divAddUserAlert").html("");

    $("#txtAddUserDisplayName").val("");
    $("#txtAddUserUsername").val("");
    $("#txtAddUserPassword").val("");
    $("#txtAddUserConfirmPassword").val("");

    $("#modalAddUser").modal("show");

    setTimeout(function () {
        $("#txtAddUserDisplayName").trigger("focus");
    }, 1000);
}

function addUser(objBtn) {
    var btn = $(objBtn);
    var divAddUserAlert = $("#divAddUserAlert");

    var user = $("#txtAddUserUsername").val();
    if (user === "") {
        showAlert("warning", "Missing!", "Please enter an username to add user.", divAddUserAlert);
        $("#txtAddUserUsername").trigger("focus");
        return;
    }

    var pass = $("#txtAddUserPassword").val();
    if (pass === "") {
        showAlert("warning", "Missing!", "Please enter a password to add user.", divAddUserAlert);
        $("#txtAddUserPassword").trigger("focus");
        return;
    }

    var confirmPass = $("#txtAddUserConfirmPassword").val();
    if (confirmPass === "") {
        showAlert("warning", "Missing!", "Please enter confirm password.", divAddUserAlert);
        $("#txtAddUserConfirmPassword").trigger("focus");
        return;
    }

    if (pass !== confirmPass) {
        showAlert("warning", "Mismatch!", "Passwords do not match. Please try again.", divAddUserAlert);
        $("#txtAddUserConfirmPassword").trigger("focus");
        return;
    }

    var displayName = $("#txtAddUserDisplayName").val();

    btn.button("loading");

    HTTPRequest({
        url: "api/admin/users/create",
        token: sessionData.token,
        method: "POST",
        data: "displayName=" + encodeURIComponent(displayName) + "&user=" + encodeURIComponent(user) + "&pass=" + encodeURIComponent(pass),
        processData: false,
        success: function (responseJSON) {
            btn.button("reset");
            $("#modalAddUser").modal("hide");

            var id = Math.floor(Math.random() * 1000000);
            var tableHtmlRow = getAdminUsersRowHtml(id, responseJSON.response);
            $("#tableAdminUsers").prepend(tableHtmlRow);

            var totalUsers = $('#tableAdminUsers >tbody >tr').length;
            $("#tfootAdminUsers").html("Total Users: " + totalUsers);

            showAlert("success", "User Added!", "User was added successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalAddUser").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divAddUserAlert
    });
}

function showUserDetailsModal(objMenuItem) {
    var divUserDetailsAlert = $("#divUserDetailsAlert");
    var divUserDetailsLoader = $("#divUserDetailsLoader");
    var divUserDetailsViewer = $("#divUserDetailsViewer");

    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var username = mnuItem.attr("data-username");

    divUserDetailsLoader.show();
    divUserDetailsViewer.hide();

    var modalUserDetails = $("#modalUserDetails");
    modalUserDetails.modal("show");

    HTTPRequest({
        url: "api/admin/users/get?user=" + encodeURIComponent(username) + "&includeGroups=true",
        token: sessionData.token,
        success: function (responseJSON) {
            $("#txtUserDetailsDisplayName").prop("disabled", responseJSON.response.isSsoUser);
            $("#txtUserDetailsDisplayName").val(responseJSON.response.displayName);

            $("#txtUserDetailsUsername").prop("disabled", responseJSON.response.isSsoUser);
            $("#txtUserDetailsUsername").val(responseJSON.response.username);

            if (responseJSON.response.isSsoUser) {
                $("#lblUserDetailsUserType").text("Remote/SSO");
                $("#lblUserDetails2FAStatus").text("SSO Managed");
            }
            else {
                $("#lblUserDetailsUserType").text("Local");
                $("#lblUserDetails2FAStatus").text(responseJSON.response.totpEnabled ? "Enabled" : "Disabled");
            }

            $("#chkUserDetailsDisableAccount").prop("checked", responseJSON.response.disabled);
            $("#txtUserDetailsSessionTimeout").val(responseJSON.response.sessionTimeoutSeconds);

            var memberOf = "";

            for (var i = 0; i < responseJSON.response.memberOfGroups.length; i++) {
                memberOf += htmlEncode(responseJSON.response.memberOfGroups[i]) + "\n";
            }

            $("#txtUserDetailsMemberOf").prop("disabled", responseJSON.response.isSsoUser && responseJSON.response.ssoManagedGroups)
            $("#optUserDetailsGroupList").prop("disabled", responseJSON.response.isSsoUser && responseJSON.response.ssoManagedGroups)

            $("#txtUserDetailsMemberOf").val(memberOf);

            var groupListHtml = "<option value=\"blank\" selected></option><option value=\"none\">None</option>";

            for (var i = 0; i < responseJSON.response.groups.length; i++) {
                groupListHtml += "<option>" + htmlEncode(responseJSON.response.groups[i]) + "</option>";
            }

            $("#optUserDetailsGroupList").html(groupListHtml);

            var sessionHtmlRows = "";

            for (var i = 0; i < responseJSON.response.sessions.length; i++) {
                var session;

                if (responseJSON.response.sessions[i].tokenName == null)
                    session = htmlEncode("[" + responseJSON.response.sessions[i].partialToken + "]");
                else
                    session = htmlEncode(responseJSON.response.sessions[i].tokenName) + "<br />[" + htmlEncode(responseJSON.response.sessions[i].partialToken) + "]";

                if (responseJSON.response.sessions[i].isCurrentSession)
                    session += "<br />(current)";

                switch (responseJSON.response.sessions[i].type) {
                    case "Standard":
                        session += "<br /><span class=\"label label-default\">Standard</span>";
                        break;

                    case "ApiToken":
                        session += "<br /><span class=\"label label-info\">API Token</span>";
                        break;

                    case "ClusterApiToken":
                        session += "<br /><span class=\"label label-primary\">Cluster API Token</span>";
                        break;

                    default:
                        session += "<br /><span class=\"label label-warning\">Unknown</span>";
                        break;
                }

                sessionHtmlRows += "<tr id=\"trUserDetailsActiveSessions" + i + "\"><td style=\"min-width: 155px; word-wrap: anywhere;\">" + session + "</td><td>" +
                    htmlEncode(moment(responseJSON.response.sessions[i].lastSeen).local().format("YYYY-MM-DD HH:mm:ss")) + "<br /><span style=\"font-size: 12px\">" + htmlEncode("(" + moment(responseJSON.response.sessions[i].lastSeen).fromNow() + ")") + "</span></td><td>" +
                    htmlEncode(responseJSON.response.sessions[i].lastSeenRemoteAddress) + "</td><td style=\"word-wrap: anywhere;\">" +
                    htmlEncode(responseJSON.response.sessions[i].lastSeenUserAgent);

                sessionHtmlRows += "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnUserDetailsActiveSessionRowOption" + i + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
                sessionHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" data-session-type=\"" + responseJSON.response.sessions[i].type + "\" data-partial-token=\"" + responseJSON.response.sessions[i].partialToken + "\" onclick=\"deleteUserSession(this); return false;\">Delete Session</a></li>";
                sessionHtmlRows += "</ul></div></td></tr>";
            }

            $("#tbodyUserDetailsActiveSessions").html(sessionHtmlRows);
            $("#tfootUserDetailsActiveSessions").html("Total Sessions: " + responseJSON.response.sessions.length);

            var btnUserDetailsSave = $("#btnUserDetailsSave");

            if (id != null)
                btnUserDetailsSave.attr("data-id", id);

            btnUserDetailsSave.attr("data-username", username);

            divUserDetailsLoader.hide();
            divUserDetailsViewer.show();

            setTimeout(function () {
                $("#txtUserDetailsDisplayName").trigger("focus");
            }, 1000);
        },
        error: function () {
            divUserDetailsLoader.hide();
        },
        invalidToken: function () {
            modalUserDetails.modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divUserDetailsAlert,
        objLoaderPlaceholder: divUserDetailsLoader
    });
}

function deleteUserSession(objMenuItem) {
    var divUserDetailsAlert = $("#divUserDetailsAlert");
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var sessionType = mnuItem.attr("data-session-type");
    var partialToken = mnuItem.attr("data-partial-token");

    if (!confirm("Are you sure you want to delete the session [" + partialToken + "] ?"))
        return;

    var apiUrl = "api/admin/sessions/delete?partialToken=" + encodeURIComponent(partialToken);

    if (sessionType == "ApiToken")
        apiUrl += "&node=" + encodeURIComponent(getPrimaryClusterNodeName());

    var btn = $("#btnUserDetailsActiveSessionRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<img src='/img/loader-small.gif'/>");

    HTTPRequest({
        url: apiUrl,
        token: sessionData.token,
        success: function (responseJSON) {
            $("#trUserDetailsActiveSessions" + id).remove();

            var totalSessions = $('#tableUserDetailsActiveSessions >tbody >tr').length;
            $("#tfootUserDetailsActiveSessions").html("Total Sessions: " + totalSessions);

            showAlert("success", "Session Deleted!", "The user session was deleted successfully.", divUserDetailsAlert);
        },
        error: function () {
            btn.prop("disabled", false);
            btn.html(originalBtnHtml);
        },
        invalidToken: function () {
            $("#modalUserDetails").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divUserDetailsAlert
    });
}

function saveUserDetails(objBtn) {
    var btn = $(objBtn);
    var divUserDetailsAlert = $("#divUserDetailsAlert");

    var id = btn.attr("data-id");
    var username = btn.attr("data-username");

    var disabled = $("#chkUserDetailsDisableAccount").prop("checked");

    var sessionTimeoutSeconds = $("#txtUserDetailsSessionTimeout").val();
    if (sessionTimeoutSeconds === "")
        sessionTimeoutSeconds = 1800;

    var params = "user=" + encodeURIComponent(username) + "&disabled=" + disabled + "&sessionTimeoutSeconds=" + encodeURIComponent(sessionTimeoutSeconds);

    if (!$("#txtUserDetailsDisplayName").prop("disabled")) {
        var displayName = $("#txtUserDetailsDisplayName").val();
        params += "&displayName=" + encodeURIComponent(displayName);
    }

    if (!$("#txtUserDetailsUsername").prop("disabled")) {
        var newUsername = $("#txtUserDetailsUsername").val();
        if (newUsername !== username)
            params += "&newUser=" + encodeURIComponent(newUsername);
    }

    if (!$("#txtUserDetailsMemberOf").prop("disabled")) {
        var memberOfGroups = cleanTextList($("#txtUserDetailsMemberOf").val());
        params += "&memberOfGroups=" + encodeURIComponent(memberOfGroups);
    }

    btn.button("loading");

    HTTPRequest({
        url: "api/admin/users/set?" + params,
        token: sessionData.token,
        success: function (responseJSON) {
            if (sessionData.username === username) {
                sessionData.displayName = responseJSON.response.displayName;
                sessionData.username = responseJSON.response.username;
                $("#mnuUserDisplayName").text(sessionData.displayName);
            }

            if (id != null) {
                var tableHtmlRow = getAdminUsersRowHtml(id, responseJSON.response);
                $("#trAdminUsers" + id).replaceWith(tableHtmlRow);
            }

            btn.button("reset");
            $("#modalUserDetails").modal("hide");

            if (id == null)
                refreshAdminSessions();

            showAlert("success", "User Saved!", "User details were saved successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalUserDetails").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divUserDetailsAlert
    });
}

function disableUser(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var username = mnuItem.attr("data-username");

    if (!confirm("Are you sure you want to disable the user [" + username + "] account?"))
        return;

    var btn = $("#btnAdminUserRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<img src='/img/loader-small.gif'/>");

    HTTPRequest({
        url: "api/admin/users/set?user=" + encodeURIComponent(username) + "&disabled=true",
        token: sessionData.token,
        success: function (responseJSON) {
            var tableHtmlRow = getAdminUsersRowHtml(id, responseJSON.response);
            $("#trAdminUsers" + id).replaceWith(tableHtmlRow);

            showAlert("success", "User Disabled!", "User [" + username + "] account was disabled successfully.");
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

function enableUser(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var username = mnuItem.attr("data-username");

    var btn = $("#btnAdminUserRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<img src='/img/loader-small.gif'/>");

    HTTPRequest({
        url: "api/admin/users/set?user=" + encodeURIComponent(username) + "&disabled=false",
        token: sessionData.token,
        success: function (responseJSON) {
            var tableHtmlRow = getAdminUsersRowHtml(id, responseJSON.response);
            $("#trAdminUsers" + id).replaceWith(tableHtmlRow);

            showAlert("success", "User Enabled!", "User [" + username + "] account was enabled successfully.");
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

function showResetUserPasswordModal(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var username = mnuItem.attr("data-username");

    $("#titleChangePassword").text("Reset Password");

    hideAlert($("#divChangePasswordAlert"));
    $("#txtChangePasswordUsername").val(username);
    $("#divChangePasswordCurrentPassword").hide();
    $("#txtChangePasswordNewPassword").val("");
    $("#txtChangePasswordConfirmPassword").val("");
    $("#divChangePassword2FATOTP").hide();

    var btnChangePassword = $("#btnChangePassword");
    btnChangePassword.text("Reset");
    btnChangePassword.attr("onclick", "resetUserPassword(this); return false;");
    btnChangePassword.show();

    $("#modalChangePassword").modal("show");

    setTimeout(function () {
        $("#txtChangePasswordNewPassword").trigger("focus");
    }, 1000);
}

function resetUserPassword(objBtn) {
    var btn = $(objBtn);

    var divChangePasswordAlert = $("#divChangePasswordAlert");

    var user = $("#txtChangePasswordUsername").val();
    var newPassword = $("#txtChangePasswordNewPassword").val();
    var confirmPassword = $("#txtChangePasswordConfirmPassword").val();

    if (newPassword === "") {
        showAlert("warning", "Missing!", "Please enter new password.", divChangePasswordAlert);
        $("#txtChangePasswordNewPassword").trigger("focus");
        return;
    }

    if (confirmPassword === "") {
        showAlert("warning", "Missing!", "Please enter confirm password.", divChangePasswordAlert);
        $("#txtChangePasswordConfirmPassword").trigger("focus");
        return;
    }

    if (newPassword !== confirmPassword) {
        showAlert("warning", "Mismatch!", "Passwords do not match. Please try again.", divChangePasswordAlert);
        $("#txtChangePasswordNewPassword").trigger("focus");
        return;
    }

    btn.button("loading");

    HTTPRequest({
        url: "api/admin/users/set",
        token: sessionData.token,
        method: "POST",
        data: "user=" + encodeURIComponent(user) + "&newPass=" + encodeURIComponent(newPassword),
        processData: false,
        success: function (responseJSON) {
            $("#modalChangePassword").modal("hide");
            $("#txtChangePasswordCurrentPassword").val("");
            $("#txtChangePasswordNewPassword").val("");
            $("#txtChangePasswordConfirmPassword").val("");
            $("#txtChangePassword2FATOTP").val("");
            btn.button("reset");

            showAlert("success", "Password Reset!", "Password was reset successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            showPageLogin();
        },
        objAlertPlaceholder: divChangePasswordAlert
    });
}

function adminDisable2FA(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var username = mnuItem.attr("data-username");

    if (!confirm("Are you sure you want to disable Two-factor authentication (2FA) for user [" + username + "] ?"))
        return;

    var btn = $("#btnAdminUserRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<img src='/img/loader-small.gif'/>");

    HTTPRequest({
        url: "api/admin/users/set?user=" + encodeURIComponent(username) + "&totpEnabled=false",
        token: sessionData.token,
        success: function (responseJSON) {
            if (username == sessionData.username)
                sessionData.totpEnabled = false;

            var tableHtmlRow = getAdminUsersRowHtml(id, responseJSON.response);
            $("#trAdminUsers" + id).replaceWith(tableHtmlRow);

            showAlert("success", "2FA Disabled!", "Two-factor authentication was disabled successfully for user [" + username + "].");
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

function deleteUser(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var username = mnuItem.attr("data-username");

    if (!confirm("Are you sure you want to delete the user [" + username + "] account?"))
        return;

    var btn = $("#btnAdminUserRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<img src='/img/loader-small.gif'/>");

    HTTPRequest({
        url: "api/admin/users/delete?user=" + encodeURIComponent(username),
        token: sessionData.token,
        success: function (responseJSON) {
            $("#trAdminUsers" + id).remove();

            var totalUsers = $('#tableAdminUsers >tbody >tr').length;
            $("#tfootAdminUsers").html("Total Users: " + totalUsers);

            showAlert("success", "User Deleted!", "User account was deleted successfully.");
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

function refreshAdminGroups() {
    var divAdminGroupsLoader = $("#divAdminGroupsLoader");
    var divAdminGroupsView = $("#divAdminGroupsView");

    divAdminGroupsLoader.show();
    divAdminGroupsView.hide();

    HTTPRequest({
        url: "api/admin/groups/list",
        token: sessionData.token,
        success: function (responseJSON) {
            var tableHtmlRows = "";

            for (var i = 0; i < responseJSON.response.groups.length; i++) {
                tableHtmlRows += getAdminGroupsRowHtml(i, responseJSON.response.groups[i]);
            }

            $("#tbodyAdminGroups").html(tableHtmlRows);
            $("#tfootAdminGroups").html("Total Groups: " + responseJSON.response.groups.length);

            divAdminGroupsLoader.hide();
            divAdminGroupsView.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divAdminGroupsLoader
    });
}

function getAdminGroupsRowHtml(id, group) {
    var tableHtmlRows = "<tr id=\"trAdminGroups" + id + "\"><td style=\"word-wrap: anywhere;\"><a href=\"#\" data-id=\"" + id + "\" data-group=\"" + htmlEncode(group.name) + "\" onclick=\"showGroupDetailsModal(this); return false;\">" + htmlEncode(group.name) + "</a></td><td style=\"word-wrap: anywhere;\">" +
        htmlEncode(group.description).replace(/\n/g, "<br />");

    tableHtmlRows += "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnAdminGroupRowOption" + id + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
    tableHtmlRows += "<li><a href=\"#\" data-id=\"" + id + "\" data-group=\"" + htmlEncode(group.name) + "\" onclick=\"showGroupDetailsModal(this); return false;\">View Details</a></li>";
    tableHtmlRows += "<li role=\"separator\" class=\"divider\"></li>";
    tableHtmlRows += "<li><a href=\"#\" data-id=\"" + id + "\" data-group=\"" + htmlEncode(group.name) + "\" onclick=\"deleteGroup(this); return false;\">Delete Group</a></li>";
    tableHtmlRows += "</ul></div></td></tr>";

    return tableHtmlRows;
}

function showAddGroupModal() {
    $("#divAddGroupAlert").html("");

    $("#txtAddGroupName").val("");
    $("#txtAddGroupDescription").val("");

    $("#modalAddGroup").modal("show");

    setTimeout(function () {
        $("#txtAddGroupName").trigger("focus");
    }, 1000);
}

function addGroup(objBtn) {
    var btn = $(objBtn);
    var divAddGroupAlert = $("#divAddGroupAlert");

    var group = $("#txtAddGroupName").val();
    if (group === "") {
        showAlert("warning", "Missing!", "Please enter a name to add group.", divAddGroupAlert);
        $("#txtAddGroupName").trigger("focus");
        return;
    }

    var description = $("#txtAddGroupDescription").val();

    btn.button("loading");

    HTTPRequest({
        url: "api/admin/groups/create?group=" + encodeURIComponent(group) + "&description=" + encodeURIComponent(description),
        token: sessionData.token,
        success: function (responseJSON) {
            btn.button("reset");
            $("#modalAddGroup").modal("hide");

            var id = Math.floor(Math.random() * 1000000);
            var tableHtmlRow = getAdminGroupsRowHtml(id, responseJSON.response);
            $("#tableAdminGroups").prepend(tableHtmlRow);

            var totalGroups = $('#tableAdminGroups >tbody >tr').length;
            $("#tfootAdminGroups").html("Total Groups: " + totalGroups);

            showAlert("success", "Group Added!", "Group was added successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalAddGroup").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divAddGroupAlert
    });
}

function showGroupDetailsModal(objMenuItem) {
    var divGroupDetailsAlert = $("#divGroupDetailsAlert");
    var divGroupDetailsLoader = $("#divGroupDetailsLoader");
    var divGroupDetailsViewer = $("#divGroupDetailsViewer");

    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var group = mnuItem.attr("data-group");

    divGroupDetailsLoader.show();
    divGroupDetailsViewer.hide();

    var modalGroupDetails = $("#modalGroupDetails");
    modalGroupDetails.modal("show");

    HTTPRequest({
        url: "api/admin/groups/get?group=" + encodeURIComponent(group) + "&includeUsers=true",
        token: sessionData.token,
        success: function (responseJSON) {
            $("#txtGroupDetailsName").val(responseJSON.response.name);
            $("#txtGroupDetailsDescription").val(responseJSON.response.description);

            var members = "";

            for (var i = 0; i < responseJSON.response.members.length; i++) {
                members += htmlEncode(responseJSON.response.members[i]) + "\n";
            }

            $("#txtGroupDetailsMembers").val(members);

            var userListHtml = "<option value=\"blank\" selected></option><option value=\"none\">None</option>";

            for (var i = 0; i < responseJSON.response.users.length; i++) {
                userListHtml += "<option>" + htmlEncode(responseJSON.response.users[i]) + "</option>";
            }

            $("#optGroupDetailsUserList").html(userListHtml);

            var btnGroupDetailsSave = $("#btnGroupDetailsSave");
            btnGroupDetailsSave.attr("data-id", id);
            btnGroupDetailsSave.attr("data-group", group);

            divGroupDetailsLoader.hide();
            divGroupDetailsViewer.show();

            setTimeout(function () {
                $("#txtGroupDetailsName").trigger("focus");
            }, 1000);
        },
        error: function () {
            divGroupDetailsLoader.hide();
        },
        invalidToken: function () {
            modalGroupDetails.modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divGroupDetailsAlert,
        objLoaderPlaceholder: divGroupDetailsLoader
    });
}

function saveGroupDetails(objBtn) {
    var btn = $(objBtn);
    var divGroupDetailsAlert = $("#divGroupDetailsAlert");

    var id = btn.attr("data-id");
    var group = btn.attr("data-group");

    var newGroup = $("#txtGroupDetailsName").val();
    var description = $("#txtGroupDetailsDescription").val();

    var members = cleanTextList($("#txtGroupDetailsMembers").val());

    var apiUrl = "api/admin/groups/set?group=" + encodeURIComponent(group) + "&description=" + encodeURIComponent(description) + "&members=" + encodeURIComponent(members);

    if (newGroup !== group)
        apiUrl += "&newGroup=" + encodeURIComponent(newGroup);

    btn.button("loading");

    HTTPRequest({
        url: apiUrl,
        token: sessionData.token,
        success: function (responseJSON) {
            var tableHtmlRow = getAdminGroupsRowHtml(id, responseJSON.response);
            $("#trAdminGroups" + id).replaceWith(tableHtmlRow);

            btn.button("reset");
            $("#modalGroupDetails").modal("hide");

            showAlert("success", "Group Saved!", "Group details were saved successfully.");
        },
        error: function () {
            btn.button("reset");
        },
        invalidToken: function () {
            btn.button("reset");
            $("#modalGroupDetails").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divGroupDetailsAlert
    });
}

function deleteGroup(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var group = mnuItem.attr("data-group");

    if (!confirm("Are you sure you want to delete the group [" + group + "] ?"))
        return;

    var btn = $("#btnAdminGroupRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<img src='/img/loader-small.gif'/>");

    HTTPRequest({
        url: "api/admin/groups/delete?group=" + encodeURIComponent(group),
        token: sessionData.token,
        success: function (responseJSON) {
            $("#trAdminGroups" + id).remove();

            var totalGroups = $('#tableAdminGroups >tbody >tr').length;
            $("#tfootAdminGroups").html("Total Groups: " + totalGroups);

            showAlert("success", "Group Deleted!", "Group was deleted successfully.");
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

function refreshAdminPermissions() {
    var divAdminPermissionsLoader = $("#divAdminPermissionsLoader");
    var divAdminPermissionsView = $("#divAdminPermissionsView");

    divAdminPermissionsLoader.show();
    divAdminPermissionsView.hide();

    HTTPRequest({
        url: "api/admin/permissions/list",
        token: sessionData.token,
        success: function (responseJSON) {
            var tableHtmlRows = "";

            for (var i = 0; i < responseJSON.response.permissions.length; i++) {
                tableHtmlRows += getAdminPermissionsRowHtml(i, responseJSON.response.permissions[i]);
            }

            $("#tbodyAdminPermissions").html(tableHtmlRows);
            $("#tfootAdminPermissions").html("Total Sections: " + responseJSON.response.permissions.length);

            divAdminPermissionsLoader.hide();
            divAdminPermissionsView.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divAdminPermissionsLoader
    });
}

function getAdminPermissionsRowHtml(id, permission) {
    var userPermissionsHtml = "<table class=\"table\" style=\"background: transparent;\"><thead><tr><th>Username</th><th style=\"width: 70px;\">View</th><th style=\"width: 70px;\">Modify</th><th style=\"width: 70px;\">Delete</th></tr></thead><tbody>";

    for (var i = 0; i < permission.userPermissions.length; i++) {
        userPermissionsHtml += "<tr><td style=\"word-wrap: anywhere;\">" + htmlEncode(permission.userPermissions[i].username) + "</td><td>" +
            (permission.userPermissions[i].canView ? "<span class=\"glyphicon glyphicon-ok\"></span>" : "") + "</td><td>" +
            (permission.userPermissions[i].canModify ? "<span class=\"glyphicon glyphicon-ok\"></span>" : "") + "</td><td>" +
            (permission.userPermissions[i].canDelete ? "<span class=\"glyphicon glyphicon-ok\"></span>" : "") + "</td></tr>";
    }

    userPermissionsHtml += "</tbody>";

    if (permission.userPermissions.length == 0)
        userPermissionsHtml += "<tfoot><tr><th colspan=\"4\" style=\"text-align: center;\">No user permissions</th></tfoot>";

    userPermissionsHtml += "</table>";

    var groupPermissionsHtml = "<table class=\"table\" style=\"background: transparent;\"><thead><tr><th>Group</th><th style=\"width: 70px;\">View</th><th style=\"width: 70px;\">Modify</th><th style=\"width: 70px;\">Delete</th></tr></thead><tbody>";

    for (var i = 0; i < permission.groupPermissions.length; i++) {
        groupPermissionsHtml += "<tr><td style=\"word-wrap: anywhere;\">" + htmlEncode(permission.groupPermissions[i].name) + "</td><td>" +
            (permission.groupPermissions[i].canView ? "<span class=\"glyphicon glyphicon-ok\"></span>" : "") + "</td><td>" +
            (permission.groupPermissions[i].canModify ? "<span class=\"glyphicon glyphicon-ok\"></span>" : "") + "</td><td>" +
            (permission.groupPermissions[i].canDelete ? "<span class=\"glyphicon glyphicon-ok\"></span>" : "") + "</td></tr>";
    }

    groupPermissionsHtml += "</tbody>";

    if (permission.groupPermissions.length == 0)
        groupPermissionsHtml += "<tfoot><tr><th colspan=\"4\" style=\"text-align: center;\">No group permissions</th></tfoot>";

    groupPermissionsHtml += "</table>";

    var tableHtmlRows = "<tr id=\"trAdminPermissions" + id + "\"><td><a href=\"#\" data-id=\"" + id + "\" data-section=\"" + htmlEncode(permission.section) + "\" onclick=\"showEditSectionPermissionsModal(this); return false;\">" + htmlEncode(permission.section) + "</a></td><td>" +
        userPermissionsHtml + "</td><td>" +
        groupPermissionsHtml;

    tableHtmlRows += "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnAdminPermissionRowOption" + id + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
    tableHtmlRows += "<li><a href=\"#\" data-id=\"" + id + "\" data-section=\"" + htmlEncode(permission.section) + "\" onclick=\"showEditSectionPermissionsModal(this); return false;\">Edit Permissions</a></li>";
    tableHtmlRows += "</ul></div></td></tr>";

    return tableHtmlRows;
}

function showEditSectionPermissionsModal(objMenuItem) {
    var divEditPermissionsAlert = $("#divEditPermissionsAlert");
    var divEditPermissionsLoader = $("#divEditPermissionsLoader");
    var divEditPermissionsViewer = $("#divEditPermissionsViewer");

    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var section = mnuItem.attr("data-section");

    $("#lblEditPermissionsName").text(section);
    $("#tbodyEditPermissionsUser").html("");
    $("#tbodyEditPermissionsGroup").html("");

    divEditPermissionsLoader.show();
    divEditPermissionsViewer.hide();

    var btnEditPermissionsSave = $("#btnEditPermissionsSave");
    btnEditPermissionsSave.attr("onclick", "saveSectionPermissions(this); return false;");
    btnEditPermissionsSave.show();

    var modalEditPermissions = $("#modalEditPermissions");
    modalEditPermissions.modal("show");

    HTTPRequest({
        url: "api/admin/permissions/get?section=" + section + "&includeUsersAndGroups=true",
        token: sessionData.token,
        success: function (responseJSON) {
            $("#lblEditPermissionsName").text(responseJSON.response.section);

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

            btnEditPermissionsSave.attr("data-id", id);
            btnEditPermissionsSave.attr("data-section", responseJSON.response.section);

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

function addEditPermissionUserRow(id, username, canView, canModify, canDelete) {
    if (id == null)
        id = Math.floor(Math.random() * 10000);

    var tableHtmlRow = "<tr id=\"trEditPermissionsUserRow" + id + "\"><td style=\"word-wrap: anywhere;\">" + htmlEncode(username) + "<input type=\"hidden\" value=\"" + htmlEncode(username) + "\"></td>";
    tableHtmlRow += "<td><input type=\"checkbox\"" + (canView ? " checked" : "") + "></td>";
    tableHtmlRow += "<td><input type=\"checkbox\"" + (canModify ? " checked" : "") + "></td>";
    tableHtmlRow += "<td><input type=\"checkbox\"" + (canDelete ? " checked" : "") + "></td>";
    tableHtmlRow += "<td align=\"right\"><button type=\"button\" class=\"btn btn-warning\" style=\"font-size: 12px; padding: 2px 0px; width: 60px;\" onclick=\"$('#trEditPermissionsUserRow" + id + "').remove();\">Remove</button></td></tr>";

    $("#tbodyEditPermissionsUser").append(tableHtmlRow);
}

function addEditPermissionGroupRow(id, name, canView, canModify, canDelete) {
    if (id == null)
        id = Math.floor(Math.random() * 10000);

    var tableHtmlRow = "<tr id=\"trEditPermissionsGroupRow" + id + "\"><td style=\"word-wrap: anywhere;\">" + htmlEncode(name) + "<input type=\"hidden\" value=\"" + htmlEncode(name) + "\"></td>";
    tableHtmlRow += "<td><input type=\"checkbox\"" + (canView ? " checked" : "") + "></td>";
    tableHtmlRow += "<td><input type=\"checkbox\"" + (canModify ? " checked" : "") + "></td>";
    tableHtmlRow += "<td><input type=\"checkbox\"" + (canDelete ? " checked" : "") + "></td>";
    tableHtmlRow += "<td align=\"right\"><button type=\"button\" class=\"btn btn-warning\" style=\"font-size: 12px; padding: 2px 0px; width: 60px;\" onclick=\"$('#trEditPermissionsGroupRow" + id + "').remove();\">Remove</button></td></tr>";

    $("#tbodyEditPermissionsGroup").append(tableHtmlRow);
}

function saveSectionPermissions(objBtn) {
    var btn = $(objBtn);
    var divEditPermissionsAlert = $("#divEditPermissionsAlert");

    var id = btn.attr("data-id");
    var section = btn.attr("data-section");

    var userPermissions = serializeTableData($("#tableEditPermissionsUser"), 4);
    var groupPermissions = serializeTableData($("#tableEditPermissionsGroup"), 4);

    var apiUrl = "api/admin/permissions/set?section=" + encodeURIComponent(section) + "&userPermissions=" + encodeURIComponent(userPermissions) + "&groupPermissions=" + encodeURIComponent(groupPermissions) + "&node=" + encodeURIComponent(getPrimaryClusterNodeName());

    btn.button("loading");

    HTTPRequest({
        url: apiUrl,
        token: sessionData.token,
        success: function (responseJSON) {
            var tableHtmlRow = getAdminPermissionsRowHtml(id, responseJSON.response);
            $("#trAdminPermissions" + id).replaceWith(tableHtmlRow);

            btn.button("reset");
            $("#modalEditPermissions").modal("hide");

            showAlert("success", "Permissions Saved!", "Section permissions were saved successfully.");
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

function refreshAdminSsoConfig() {
    var divAdminSsoLoader = $("#divAdminSsoLoader");
    var divAdminSsoView = $("#divAdminSsoView");

    divAdminSsoLoader.show();
    divAdminSsoView.hide();

    HTTPRequest({
        url: "api/admin/sso/get?includeGroups=true",
        token: sessionData.token,
        success: function (responseJSON) {
            localGroups = responseJSON.response.localGroups;

            loadAdminSsoConfig(responseJSON);

            divAdminSsoLoader.hide();
            divAdminSsoView.show();
        },
        invalidToken: function () {
            showPageLogin();
        },
        objLoaderPlaceholder: divAdminSsoLoader
    });
}

function loadAdminSsoConfig(responseJSON) {
    $("#chkAdminSsoEnabled").prop("checked", responseJSON.response.ssoEnabled);
    $("#txtAdminSsoAuthority").val(responseJSON.response.ssoAuthority);
    $("#txtAdminSsoClientId").val(responseJSON.response.ssoClientId);
    $("#txtAdminSsoClientSecret").val(responseJSON.response.ssoClientSecret);
    $("#txtAdminSsoMetadataAddress").val(responseJSON.response.ssoMetadataAddress);
    $("#chkAdminSsoAllowSignup").prop("checked", responseJSON.response.ssoAllowSignup);
    $("#chkAdminSsoAllowSignupOnlyForMappedUsers").prop("checked", responseJSON.response.ssoAllowSignupOnlyForMappedUsers);

    $("#tableAdminSsoGroupMap").html("");

    for (var i = 0; i < responseJSON.response.ssoGroupMap.length; i++)
        addAdminSsoGroupMapRow(responseJSON.response.ssoGroupMap[i].remoteGroup, responseJSON.response.ssoGroupMap[i].localGroup);

    var redirectUri = window.location.protocol + "//" + window.location.host + window.location.pathname;
    if (redirectUri.endsWith("/"))
        redirectUri += "sso/callback";
    else
        redirectUri += "/sso/callback";

    $("#lblAdminSsoRedirectUri").text(redirectUri);
}

function addAdminSsoGroupMapRow(remoteGroup, localGroup) {
    var id = Math.floor(Math.random() * 10000);

    var tableHtmlRows = "<tr id=\"tableAdminSsoGroupMapRow" + id + "\"><td><input type=\"text\" class=\"form-control\" value=\"" + htmlEncode(remoteGroup) + "\"></td>";

    tableHtmlRows += "<td><select class=\"form-control\">";

    for (var i = 0; i < localGroups.length; i++)
        tableHtmlRows += "<option" + (localGroups[i] == localGroup ? " selected" : "") + ">" + htmlEncode(localGroups[i]) + "</option>";

    tableHtmlRows += "</select></td>";

    tableHtmlRows += "<td><button type=\"button\" class=\"btn btn-danger\" onclick=\"$('#tableAdminSsoGroupMapRow" + id + "').remove();\">Delete</button></td></tr>";

    $("#tableAdminSsoGroupMap").append(tableHtmlRows);
}

function saveAdminSsoConfig(objBtn) {
    var btn = $(objBtn);

    var ssoEnabled = $("#chkAdminSsoEnabled").prop("checked");

    var ssoAuthority = $("#txtAdminSsoAuthority").val();
    if (ssoEnabled && (ssoAuthority === "")) {
        showAlert("warning", "Missing!", "Please enter the Authority URL.");
        $("#txtAdminSsoAuthority").trigger("focus");
        return;
    }

    var ssoClientId = $("#txtAdminSsoClientId").val();
    if (ssoEnabled && (ssoClientId === "")) {
        showAlert("warning", "Missing!", "Please enter the Client ID.");
        $("#txtAdminSsoClientId").trigger("focus");
        return;
    }

    var ssoClientSecret = $("#txtAdminSsoClientSecret").val();
    if (ssoEnabled && ssoClientSecret === "") {
        showAlert("warning", "Missing!", "Please enter the Client Secret.");
        $("#txtAdminSsoClientSecret").trigger("focus");
        return;
    }

    var ssoMetadataAddress = $("#txtAdminSsoMetadataAddress").val();
    var ssoAllowSignup = $("#chkAdminSsoAllowSignup").prop("checked");
    var ssoAllowSignupOnlyForMappedUsers = $("#chkAdminSsoAllowSignupOnlyForMappedUsers").prop("checked");

    var ssoGroupMap = serializeTableData($("#tableAdminSsoGroupMap"), 2);
    if (ssoGroupMap === false)
        return;

    if (ssoGroupMap.length == 0)
        ssoGroupMap = false;

    if (ssoAuthority.startsWith("http:")) {
        if (!confirm("WARNING! The SSO Authority must use a 'https' URL scheme for production environment. Are you sure you want to proceed with using a 'http' URL scheme?")) {
            $("#txtAdminSsoAuthority").trigger("focus");
            return;
        }
    }

    if (ssoMetadataAddress.startsWith("http:")) {
        if (!confirm("WARNING! The Metadata Address must use a 'https' URL scheme for production environment. Are you sure you want to proceed with using a 'http' URL scheme?")) {
            $("#txtAdminSsoMetadataAddress").trigger("focus");
            return;
        }
    }

    btn.button("loading");

    HTTPRequest({
        url: "api/admin/sso/set",
        token: sessionData.token,
        method: "POST",
        data: "ssoEnabled=" + ssoEnabled + "&ssoAuthority=" + encodeURIComponent(ssoAuthority) + "&ssoClientId=" + encodeURIComponent(ssoClientId) + "&ssoClientSecret=" + encodeURIComponent(ssoClientSecret) + "&ssoMetadataAddress=" + encodeURIComponent(ssoMetadataAddress) + "&ssoAllowSignup=" + ssoAllowSignup + "&ssoAllowSignupOnlyForMappedUsers=" + ssoAllowSignupOnlyForMappedUsers + "&ssoGroupMap=" + encodeURIComponent(ssoGroupMap),
        success: function (responseJSON) {
            loadAdminSsoConfig(responseJSON);
            btn.button("reset");

            showAlert("success", "SSO Config Saved!", "Single Sign-On (SSO) config was saved successfully.");
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
