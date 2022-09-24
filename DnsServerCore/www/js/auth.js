/*
Technitium DNS Server
Copyright (C) 2022  Shreyas Zare (shreyas@technitium.com)

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

$(function () {
    var token = localStorage.getItem("token");
    if (token == null) {
        showPageLogin();
        login("admin", "admin");
    }
    else {
        HTTPRequest({
            url: "/api/user/session/get?token=" + token,
            success: function (responseJSON) {
                sessionData = responseJSON;
                localStorage.setItem("token", sessionData.token);

                $("#mnuUserDisplayName").text(sessionData.displayName);
                document.title = sessionData.info.dnsServerDomain + " - " + "Technitium DNS Server v" + sessionData.info.version;
                $("#lblAboutVersion").text(sessionData.info.version);
                $("#lblDnsServerDomain").text(" - " + sessionData.info.dnsServerDomain);
                $("#txtAddEditRecordTtl").attr("placeholder", sessionData.info.defaultRecordTtl);

                showPageMain();
            },
            error: function () {
                showPageLogin();
            }
        });
    }

    $("#optGroupDetailsUserList").change(function () {
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

    $("#optUserDetailsGroupList").change(function () {
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

    $("#optEditPermissionsUserList").change(function () {
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

    $("#optEditPermissionsGroupList").change(function () {
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
        $("#txtUser").focus();
        return;
    }

    if ((password === null) || (password === "")) {
        showAlert("warning", "Missing!", "Please enter a password.");
        $("#txtPass").focus();
        return;
    }

    var btn = $("#btnLogin").button('loading');

    HTTPRequest({
        url: "/api/user/login?user=" + encodeURIComponent(username) + "&pass=" + encodeURIComponent(password) + "&includeInfo=true",
        success: function (responseJSON) {
            sessionData = responseJSON;
            localStorage.setItem("token", sessionData.token);

            $("#mnuUserDisplayName").text(sessionData.displayName);
            document.title = sessionData.info.dnsServerDomain + " - " + "Technitium DNS Server v" + sessionData.info.version;
            $("#lblAboutVersion").text(sessionData.info.version);
            $("#lblDnsServerDomain").text(" - " + sessionData.info.dnsServerDomain);
            $("#txtAddEditRecordTtl").attr("placeholder", sessionData.info.defaultRecordTtl);

            showPageMain();

            if ((username === "admin") && (password === "admin"))
                showChangePasswordModal();
        },
        error: function () {
            btn.button('reset');
            $("#txtUser").focus();

            if (autoLogin)
                hideAlert();
        }
    });
}

function logout() {
    HTTPRequest({
        url: "/api/user/logout?token=" + sessionData.token,
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
    $("#txtCreateApiTokenPassword").val("");
    $("#txtCreateApiTokenName").val("");

    $("#txtCreateApiTokenUsername").show();
    $("#optCreateApiTokenUsername").hide();
    $("#divCreateApiTokenPassword").show();

    $("#divCreateApiTokenLoader").hide();
    $("#divCreateApiTokenForm").show();
    $("#divCreateApiTokenOutput").hide();

    var btnCreateApiToken = $("#btnCreateApiToken");
    btnCreateApiToken.attr("onclick", "createMyApiToken(this); return false;");
    btnCreateApiToken.show();

    $("#modalCreateApiToken").modal("show");

    setTimeout(function () {
        $("#txtCreateApiTokenPassword").focus();
    }, 1000);
}

function createMyApiToken(objBtn) {
    var btn = $(objBtn);

    var divCreateApiTokenAlert = $("#divCreateApiTokenAlert");

    var user = $("#txtCreateApiTokenUsername").val();
    var password = $("#txtCreateApiTokenPassword").val();
    var tokenName = $("#txtCreateApiTokenName").val();

    if (password === "") {
        showAlert("warning", "Missing!", "Please enter a password.", divCreateApiTokenAlert);
        $("#txtCreateApiTokenPassword").focus();
        return;
    }

    if (tokenName === "") {
        showAlert("warning", "Missing!", "Please enter a token name.", divCreateApiTokenAlert);
        $("#txtCreateApiTokenName").focus();
        return;
    }

    btn.button('loading');

    HTTPRequest({
        url: "/api/user/createToken?user=" + encodeURIComponent(user) + "&pass=" + encodeURIComponent(password) + "&tokenName=" + encodeURIComponent(tokenName),
        success: function (responseJSON) {
            btn.button('reset');
            btn.hide();

            $("#lblCreateApiTokenOutputUsername").text(responseJSON.username);
            $("#lblCreateApiTokenOutputTokenName").text(responseJSON.tokenName);
            $("#lblCreateApiTokenOutputToken").text(responseJSON.token);

            $("#divCreateApiTokenForm").hide();
            $("#divCreateApiTokenOutput").show();

            showAlert("success", "Token Created!", "API token was created successfully.", divCreateApiTokenAlert);
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
            $("#modalCreateApiToken").hide("");
            showPageLogin();
        },
        objAlertPlaceholder: divCreateApiTokenAlert
    });
}

function showChangePasswordModal() {
    $("#titleChangePassword").text("Change Password");

    $("#divChangePasswordAlert").html("");
    $("#txtChangePasswordUsername").val(sessionData.username);
    $("#txtChangePasswordNewPassword").val("");
    $("#txtChangePasswordConfirmPassword").val("");

    var btnChangePassword = $("#btnChangePassword");
    btnChangePassword.text("Change");
    btnChangePassword.attr("onclick", "changePassword(this); return false;");
    btnChangePassword.show();

    $("#modalChangePassword").modal("show");

    setTimeout(function () {
        $("#txtChangePasswordNewPassword").focus();
    }, 1000);
}

function changePassword(objBtn) {
    var btn = $(objBtn);

    var divChangePasswordAlert = $("#divChangePasswordAlert");
    var newPassword = $("#txtChangePasswordNewPassword").val();
    var confirmPassword = $("#txtChangePasswordConfirmPassword").val();

    if ((newPassword === null) || (newPassword === "")) {
        showAlert("warning", "Missing!", "Please enter new password.", divChangePasswordAlert);
        $("#txtChangePasswordNewPassword").focus();
        return;
    }

    if ((confirmPassword === null) || (confirmPassword === "")) {
        showAlert("warning", "Missing!", "Please enter confirm password.", divChangePasswordAlert);
        $("#txtChangePasswordConfirmPassword").focus();
        return;
    }

    if (newPassword !== confirmPassword) {
        showAlert("warning", "Mismatch!", "Passwords do not match. Please try again.", divChangePasswordAlert);
        $("#txtChangePasswordNewPassword").focus();
        return;
    }

    btn.button('loading');

    HTTPRequest({
        url: "/api/user/changePassword?token=" + sessionData.token + "&pass=" + encodeURIComponent(newPassword),
        success: function (responseJSON) {
            $("#modalChangePassword").modal("hide");
            btn.button('reset');

            showAlert("success", "Password Changed!", "Password was changed successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
            showPageLogin();
        },
        objAlertPlaceholder: divChangePasswordAlert
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
        url: "/api/user/profile/get?token=" + sessionData.token,
        success: function (responseJSON) {
            sessionData.displayName = responseJSON.response.displayName;
            sessionData.username = responseJSON.response.username;
            $("#mnuUserDisplayName").text(sessionData.displayName);

            $("#txtMyProfileDisplayName").val(responseJSON.response.displayName);
            $("#txtMyProfileUsername").val(responseJSON.response.username);
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

                        default:
                            session += "<br /><span class=\"label label-warning\">Unknown</span>";
                            break;
                    }

                    sessionHtmlRows += "<tr id=\"trMyProfileActiveSessions" + i + "\"><td style=\"min-width: 155px; word-wrap: anywhere;\">" + session + "</td><td>" +
                        htmlEncode(moment(responseJSON.response.sessions[i].lastSeen).local().format("YYYY-MM-DD HH:mm:ss")) + "<br />" + htmlEncode("(" + moment(responseJSON.response.sessions[i].lastSeen).fromNow() + ")") + "</td><td>" +
                        htmlEncode(responseJSON.response.sessions[i].lastSeenRemoteAddress) + "</td><td style=\"word-wrap: anywhere;\">" +
                        htmlEncode(responseJSON.response.sessions[i].lastSeenUserAgent);

                    sessionHtmlRows += "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnMyProfileActiveSessionRowOption" + i + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
                    sessionHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" data-partial-token=\"" + responseJSON.response.sessions[i].partialToken + "\" onclick=\"deleteMySession(this); return false;\">Delete Session</a></li>";
                    sessionHtmlRows += "</ul></div></td></tr>";
                }

                $("#tbodyMyProfileActiveSessions").html(sessionHtmlRows);
                $("#tfootMyProfileActiveSessions").html("Total Sessions: " + responseJSON.response.sessions.length);
            }

            divMyProfileLoader.hide();
            divMyProfileViewer.show();

            setTimeout(function () {
                $("#txtMyProfileDisplayName").focus();
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

    var displayName = $("#txtMyProfileDisplayName").val();
    if (displayName === "")
        displayName = $("#txtMyProfileUsername").val();

    var sessionTimeoutSeconds = $("#txtMyProfileSessionTimeout").val();
    if (sessionTimeoutSeconds === "")
        sessionTimeoutSeconds = 1800;

    var apiUrl = "/api/user/profile/set?token=" + sessionData.token + "&displayName=" + encodeURIComponent(displayName) + "&sessionTimeoutSeconds=" + encodeURIComponent(sessionTimeoutSeconds);

    btn.button('loading');

    HTTPRequest({
        url: apiUrl,
        success: function (responseJSON) {
            sessionData.displayName = responseJSON.response.displayName;
            $("#mnuUserDisplayName").text(sessionData.displayName);

            btn.button('reset');
            $("#modalMyProfile").modal("hide");

            showAlert("success", "Profile Saved!", "User profile was saved successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
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
    var partialToken = mnuItem.attr("data-partial-token");

    if (!confirm("Are you sure you want to delete the session [" + partialToken + "] ?"))
        return;

    var apiUrl = "/api/user/session/delete?token=" + sessionData.token + "&partialToken=" + encodeURIComponent(partialToken);

    var btn = $("#btnMyProfileActiveSessionRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<img src='/img/loader-small.gif'/>");

    HTTPRequest({
        url: apiUrl,
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
    else
        refreshAdminSessions();
}

function refreshAdminSessions() {
    var divAdminSessionsLoader = $("#divAdminSessionsLoader");
    var divAdminSessionsView = $("#divAdminSessionsView");

    divAdminSessionsLoader.show();
    divAdminSessionsView.hide();

    HTTPRequest({
        url: "/api/admin/sessions/list?token=" + sessionData.token,
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

                    default:
                        session += "<br /><span class=\"label label-warning\">Unknown</span>";
                        break;
                }

                tableHtmlRows += "<tr id=\"trAdminSessions" + i + "\"><td>" + htmlEncode(responseJSON.response.sessions[i].username) + "</td><td style=\"min-width: 155px; word-wrap: anywhere;\">" +
                    session + "</td><td>" +
                    htmlEncode(moment(responseJSON.response.sessions[i].lastSeen).local().format("YYYY-MM-DD HH:mm:ss")) + "<br />" + htmlEncode("(" + moment(responseJSON.response.sessions[i].lastSeen).fromNow() + ")") + "</td><td>" +
                    htmlEncode(responseJSON.response.sessions[i].lastSeenRemoteAddress) + "</td><td style=\"word-wrap: anywhere;\">" +
                    htmlEncode(responseJSON.response.sessions[i].lastSeenUserAgent);

                tableHtmlRows += "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnAdminSessionRowOption" + i + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
                tableHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" data-partial-token=\"" + responseJSON.response.sessions[i].partialToken + "\" onclick=\"deleteAdminSession(this); return false;\">Delete Session</a></li>";
                tableHtmlRows += "</ul></div></td></tr>";
            }

            $("#tbodyAdminSessions").html(tableHtmlRows);
            $("#tfootAdminSessions").html("Total Sessions: " + responseJSON.response.sessions.length);

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
        url: "/api/admin/users/list?token=" + sessionData.token,
        success: function (responseJSON) {
            var userListHtml = "";

            for (var i = 0; i < responseJSON.response.users.length; i++) {
                userListHtml += "<option>" + htmlEncode(responseJSON.response.users[i].username) + "</option>";
            }

            $("#optCreateApiTokenUsername").html(userListHtml);

            $("#optCreateApiTokenUsername").show();
            $("#txtCreateApiTokenUsername").hide();
            $("#divCreateApiTokenPassword").hide();
            $("#txtCreateApiTokenName").val("");

            divCreateApiTokenLoader.hide();
            divCreateApiTokenForm.show();

            setTimeout(function () {
                $("#optCreateApiTokenUsername").focus();
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
        $("#optCreateApiTokenUsername").focus();
        return;
    }

    if (tokenName === "") {
        showAlert("warning", "Missing!", "Please enter a token name.", divCreateApiTokenAlert);
        $("#txtCreateApiTokenName").focus();
        return;
    }

    btn.button('loading');

    HTTPRequest({
        url: "/api/admin/sessions/createToken?token=" + sessionData.token + "&user=" + encodeURIComponent(user) + "&tokenName=" + encodeURIComponent(tokenName),
        success: function (responseJSON) {
            btn.button('reset');
            btn.hide();

            $("#lblCreateApiTokenOutputUsername").text(responseJSON.response.username);
            $("#lblCreateApiTokenOutputTokenName").text(responseJSON.response.tokenName);
            $("#lblCreateApiTokenOutputToken").text(responseJSON.response.token);

            $("#divCreateApiTokenForm").hide();
            $("#divCreateApiTokenOutput").show();

            showAlert("success", "Token Created!", "API token was created successfully.", divCreateApiTokenAlert);
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
            $("#modalCreateApiToken").hide("");
            showPageLogin();
        },
        objAlertPlaceholder: divCreateApiTokenAlert
    });
}

function deleteAdminSession(objMenuItem) {
    var mnuItem = $(objMenuItem);

    var id = mnuItem.attr("data-id");
    var partialToken = mnuItem.attr("data-partial-token");

    if (!confirm("Are you sure you want to delete the session [" + partialToken + "] ?"))
        return;

    var apiUrl = "/api/admin/sessions/delete?token=" + sessionData.token + "&partialToken=" + encodeURIComponent(partialToken);

    var btn = $("#btnAdminSessionRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<img src='/img/loader-small.gif'/>");

    HTTPRequest({
        url: apiUrl,
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
        url: "/api/admin/users/list?token=" + sessionData.token,
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
    var status = "";
    if (user.disabled)
        status += "<span class=\"label label-warning\">Disabled</span>";
    else
        status += "<span class=\"label label-success\">Enabled</span>";

    var tableHtmlRows = "<tr id=\"trAdminUsers" + id + "\"><td style=\"word-wrap: anywhere;\"><a href=\"#\" data-id=\"" + id + "\" data-username=\"" + htmlEncode(user.username) + "\" onclick=\"showUserDetailsModal(this); return false;\">" + htmlEncode(user.username) + "</a></td><td style=\"word-wrap: anywhere;\">" +
        htmlEncode(user.displayName) + "</td><td>" +
        status + "</td><td>" +
        htmlEncode(moment(user.previousSessionLoggedOn).local().format("YYYY-MM-DD HH:mm:ss")) + " from " + htmlEncode(user.previousSessionRemoteAddress) + "</td><td>" +
        htmlEncode(moment(user.recentSessionLoggedOn).local().format("YYYY-MM-DD HH:mm:ss")) + " from " + htmlEncode(user.recentSessionRemoteAddress);

    tableHtmlRows += "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnAdminUserRowOption" + id + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
    tableHtmlRows += "<li><a href=\"#\" data-id=\"" + id + "\" data-username=\"" + htmlEncode(user.username) + "\" onclick=\"showUserDetailsModal(this); return false;\">View Details</a></li>";
    tableHtmlRows += "<li id=\"mnuAdminUserRowEnable" + id + "\"" + (user.disabled ? "" : " style=\"display: none;\"") + "><a href=\"#\" data-id=\"" + id + "\" data-username=\"" + htmlEncode(user.username) + "\" onclick=\"enableUser(this); return false;\">Enable</a></li>";
    tableHtmlRows += "<li id=\"mnuAdminUserRowDisable" + id + "\"" + (!user.disabled ? "" : " style=\"display: none;\"") + "><a href=\"#\" data-id=\"" + id + "\" data-username=\"" + htmlEncode(user.username) + "\" onclick=\"disableUser(this); return false;\">Disable</a></li>";
    tableHtmlRows += "<li><a href=\"#\" data-id=\"" + id + "\" data-username=\"" + htmlEncode(user.username) + "\" onclick=\"showResetUserPasswordModal(this); return false;\">Reset Password</a></li>";
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
        $("#txtAddUserDisplayName").focus();
    }, 1000);
}

function addUser(objBtn) {
    var btn = $(objBtn);
    var divAddUserAlert = $("#divAddUserAlert");

    var user = $("#txtAddUserUsername").val();
    if (user === "") {
        showAlert("warning", "Missing!", "Please enter an username to add user.", divAddUserAlert);
        $("#txtAddUserUsername").focus();
        return;
    }

    var pass = $("#txtAddUserPassword").val();
    if (pass === "") {
        showAlert("warning", "Missing!", "Please enter a password to add user.", divAddUserAlert);
        $("#txtAddUserPassword").focus();
        return;
    }

    var confirmPass = $("#txtAddUserConfirmPassword").val();
    if (confirmPass === "") {
        showAlert("warning", "Missing!", "Please enter confirm password.", divAddUserAlert);
        $("#txtAddUserConfirmPassword").focus();
        return;
    }

    if (pass !== confirmPass) {
        showAlert("warning", "Mismatch!", "Passwords do not match. Please try again.", divAddUserAlert);
        $("#txtAddUserConfirmPassword").focus();
        return;
    }

    var displayName = $("#txtAddUserDisplayName").val();
    if (displayName === "")
        displayName = user;

    btn.button('loading');

    HTTPRequest({
        url: "/api/admin/users/create?token=" + sessionData.token + "&displayName=" + encodeURIComponent(displayName) + "&user=" + encodeURIComponent(user) + "&pass=" + encodeURIComponent(pass),
        success: function (responseJSON) {
            btn.button('reset');
            $("#modalAddUser").modal("hide");

            var id = Math.floor(Math.random() * 1000000);
            var tableHtmlRow = getAdminUsersRowHtml(id, responseJSON.response);
            $("#tableAdminUsers").prepend(tableHtmlRow);

            var totalUsers = $('#tableAdminUsers >tbody >tr').length;
            $("#tfootAdminUsers").html("Total Users: " + totalUsers);

            showAlert("success", "User Added!", "User was added successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
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
        url: "/api/admin/users/get?token=" + sessionData.token + "&user=" + username + "&includeGroups=true",
        success: function (responseJSON) {
            $("#txtUserDetailsDisplayName").val(responseJSON.response.displayName);
            $("#txtUserDetailsUsername").val(responseJSON.response.username);
            $("#chkUserDetailsDisableAccount").prop("checked", responseJSON.response.disabled);
            $("#txtUserDetailsSessionTimeout").val(responseJSON.response.sessionTimeoutSeconds);

            var memberOf = "";

            for (var i = 0; i < responseJSON.response.memberOfGroups.length; i++) {
                memberOf += htmlEncode(responseJSON.response.memberOfGroups[i]) + "\n";
            }

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

                    default:
                        session += "<br /><span class=\"label label-warning\">Unknown</span>";
                        break;
                }

                sessionHtmlRows += "<tr id=\"trUserDetailsActiveSessions" + i + "\"><td style=\"min-width: 155px; word-wrap: anywhere;\">" + session + "</td><td>" +
                    htmlEncode(moment(responseJSON.response.sessions[i].lastSeen).local().format("YYYY-MM-DD HH:mm:ss")) + "<br />" + htmlEncode("(" + moment(responseJSON.response.sessions[i].lastSeen).fromNow() + ")") + "</td><td>" +
                    htmlEncode(responseJSON.response.sessions[i].lastSeenRemoteAddress) + "</td><td style=\"word-wrap: anywhere;\">" +
                    htmlEncode(responseJSON.response.sessions[i].lastSeenUserAgent);

                sessionHtmlRows += "</td><td align=\"right\"><div class=\"dropdown\"><a href=\"#\" id=\"btnUserDetailsActiveSessionRowOption" + i + "\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" aria-haspopup=\"true\" aria-expanded=\"true\"><span class=\"glyphicon glyphicon-option-vertical\" aria-hidden=\"true\"></span></a><ul class=\"dropdown-menu dropdown-menu-right\">";
                sessionHtmlRows += "<li><a href=\"#\" data-id=\"" + i + "\" data-partial-token=\"" + responseJSON.response.sessions[i].partialToken + "\" onclick=\"deleteUserSession(this); return false;\">Delete Session</a></li>";
                sessionHtmlRows += "</ul></div></td></tr>";
            }

            $("#tbodyUserDetailsActiveSessions").html(sessionHtmlRows);
            $("#tfootUserDetailsActiveSessions").html("Total Sessions: " + responseJSON.response.sessions.length);

            var btnUserDetailsSave = $("#btnUserDetailsSave");
            btnUserDetailsSave.attr("data-id", id);
            btnUserDetailsSave.attr("data-username", username);

            divUserDetailsLoader.hide();
            divUserDetailsViewer.show();

            setTimeout(function () {
                $("#txtUserDetailsDisplayName").focus();
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
    var partialToken = mnuItem.attr("data-partial-token");

    if (!confirm("Are you sure you want to delete the session [" + partialToken + "] ?"))
        return;

    var apiUrl = "/api/admin/sessions/delete?token=" + sessionData.token + "&partialToken=" + encodeURIComponent(partialToken);

    var btn = $("#btnUserDetailsActiveSessionRowOption" + id);
    var originalBtnHtml = btn.html();
    btn.prop("disabled", true);
    btn.html("<img src='/img/loader-small.gif'/>");

    HTTPRequest({
        url: apiUrl,
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

    var newUsername = $("#txtUserDetailsUsername").val();

    var displayName = $("#txtUserDetailsDisplayName").val();
    if (displayName === "")
        displayName = newUsername;

    var disabled = $("#chkUserDetailsDisableAccount").prop("checked");

    var sessionTimeoutSeconds = $("#txtUserDetailsSessionTimeout").val();
    if (sessionTimeoutSeconds === "")
        sessionTimeoutSeconds = 1800;

    var memberOfGroups = cleanTextList($("#txtUserDetailsMemberOf").val());

    var apiUrl = "/api/admin/users/set?token=" + sessionData.token + "&user=" + encodeURIComponent(username) + "&displayName=" + encodeURIComponent(displayName) + "&disabled=" + disabled + "&sessionTimeoutSeconds=" + encodeURIComponent(sessionTimeoutSeconds) + "&memberOfGroups=" + encodeURIComponent(memberOfGroups);

    if (newUsername !== username)
        apiUrl += "&newUser=" + encodeURIComponent(newUsername);

    btn.button('loading');

    HTTPRequest({
        url: apiUrl,
        success: function (responseJSON) {
            if (sessionData.username === username) {
                sessionData.displayName = responseJSON.response.displayName;
                sessionData.username = responseJSON.response.username;
                $("#mnuUserDisplayName").text(sessionData.displayName);
            }

            var tableHtmlRow = getAdminUsersRowHtml(id, responseJSON.response);
            $("#trAdminUsers" + id).replaceWith(tableHtmlRow);

            btn.button('reset');
            $("#modalUserDetails").modal("hide");

            showAlert("success", "User Saved!", "User details were saved successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
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
        url: "/api/admin/users/set?token=" + sessionData.token + "&user=" + encodeURIComponent(username) + "&disabled=true",
        success: function (responseJSON) {
            var tableHtmlRow = getAdminUsersRowHtml(id, responseJSON.response);
            $("#trAdminUsers" + id).replaceWith(tableHtmlRow);

            showAlert("success", "User Disabled!", "User account was disabled successfully.");
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
        url: "/api/admin/users/set?token=" + sessionData.token + "&user=" + encodeURIComponent(username) + "&disabled=false",
        success: function (responseJSON) {
            var tableHtmlRow = getAdminUsersRowHtml(id, responseJSON.response);
            $("#trAdminUsers" + id).replaceWith(tableHtmlRow);

            showAlert("success", "User Enabled!", "User account was enabled successfully.");
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

    $("#divChangePasswordAlert").html("");
    $("#txtChangePasswordUsername").val(username);
    $("#txtChangePasswordNewPassword").val("");
    $("#txtChangePasswordConfirmPassword").val("");

    var btnChangePassword = $("#btnChangePassword");
    btnChangePassword.text("Reset");
    btnChangePassword.attr("onclick", "resetUserPassword(this); return false;");
    btnChangePassword.show();

    $("#modalChangePassword").modal("show");

    setTimeout(function () {
        $("#txtChangePasswordNewPassword").focus();
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
        $("#txtChangePasswordNewPassword").focus();
        return;
    }

    if (confirmPassword === "") {
        showAlert("warning", "Missing!", "Please enter confirm password.", divChangePasswordAlert);
        $("#txtChangePasswordConfirmPassword").focus();
        return;
    }

    if (newPassword !== confirmPassword) {
        showAlert("warning", "Mismatch!", "Passwords do not match. Please try again.", divChangePasswordAlert);
        $("#txtChangePasswordNewPassword").focus();
        return;
    }

    btn.button('loading');

    HTTPRequest({
        url: "/api/admin/users/set?token=" + sessionData.token + "&user=" + encodeURIComponent(user) + "&newPass=" + encodeURIComponent(newPassword),
        success: function (responseJSON) {
            $("#modalChangePassword").modal("hide");
            btn.button('reset');

            showAlert("success", "Password Reset!", "Password was reset successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
            showPageLogin();
        },
        objAlertPlaceholder: divChangePasswordAlert
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
        url: "/api/admin/users/delete?token=" + sessionData.token + "&user=" + encodeURIComponent(username),
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
        url: "/api/admin/groups/list?token=" + sessionData.token,
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
        $("#txtAddGroupName").focus();
    }, 1000);
}

function addGroup(objBtn) {
    var btn = $(objBtn);
    var divAddGroupAlert = $("#divAddGroupAlert");

    var group = $("#txtAddGroupName").val();
    if (group === "") {
        showAlert("warning", "Missing!", "Please enter a name to add group.", divAddGroupAlert);
        $("#txtAddGroupName").focus();
        return;
    }

    var description = $("#txtAddGroupDescription").val();

    btn.button('loading');

    HTTPRequest({
        url: "/api/admin/groups/create?token=" + sessionData.token + "&group=" + encodeURIComponent(group) + "&description=" + encodeURIComponent(description),
        success: function (responseJSON) {
            btn.button('reset');
            $("#modalAddGroup").modal("hide");

            var id = Math.floor(Math.random() * 1000000);
            var tableHtmlRow = getAdminGroupsRowHtml(id, responseJSON.response);
            $("#tableAdminGroups").prepend(tableHtmlRow);

            var totalGroups = $('#tableAdminGroups >tbody >tr').length;
            $("#tfootAdminGroups").html("Total Groups: " + totalGroups);

            showAlert("success", "Group Added!", "Group was added successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
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
        url: "/api/admin/groups/get?token=" + sessionData.token + "&group=" + group + "&includeUsers=true",
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
                $("#txtGroupDetailsName").focus();
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

    var apiUrl = "/api/admin/groups/set?token=" + sessionData.token + "&group=" + encodeURIComponent(group) + "&description=" + encodeURIComponent(description) + "&members=" + encodeURIComponent(members);

    if (newGroup !== group)
        apiUrl += "&newGroup=" + encodeURIComponent(newGroup);

    btn.button('loading');

    HTTPRequest({
        url: apiUrl,
        success: function (responseJSON) {
            var tableHtmlRow = getAdminGroupsRowHtml(id, responseJSON.response);
            $("#trAdminGroups" + id).replaceWith(tableHtmlRow);

            btn.button('reset');
            $("#modalGroupDetails").modal("hide");

            showAlert("success", "Group Saved!", "Group details were saved successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
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
        url: "/api/admin/groups/delete?token=" + sessionData.token + "&group=" + encodeURIComponent(group),
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
        url: "/api/admin/permissions/list?token=" + sessionData.token,
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
        url: "/api/admin/permissions/get?token=" + sessionData.token + "&section=" + section + "&includeUsersAndGroups=true",
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

    var apiUrl = "/api/admin/permissions/set?token=" + sessionData.token + "&section=" + encodeURIComponent(section) + "&userPermissions=" + encodeURIComponent(userPermissions) + "&groupPermissions=" + encodeURIComponent(groupPermissions);

    btn.button('loading');

    HTTPRequest({
        url: apiUrl,
        success: function (responseJSON) {
            var tableHtmlRow = getAdminPermissionsRowHtml(id, responseJSON.response);
            $("#trAdminPermissions" + id).replaceWith(tableHtmlRow);

            btn.button('reset');
            $("#modalEditPermissions").modal("hide");

            showAlert("success", "Permissions Saved!", "Section permissions were saved successfully.");
        },
        error: function () {
            btn.button('reset');
        },
        invalidToken: function () {
            btn.button('reset');
            $("#modalEditPermissions").modal("hide");
            showPageLogin();
        },
        objAlertPlaceholder: divEditPermissionsAlert
    });
}
