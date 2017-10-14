
var token = null;

$(function () {
    var headerHtml = $("#header").html();

    $("#header").html("<div class=\"title\"><a href=\"/\"><img src=\"/img/logo25x25.png\" alt=\"Technitium Logo\" /><span class=\"text\" style=\"color: #ffffff;\">Technitium</span></a>" + headerHtml + "</div>");
    $("#footer").html("<div class=\"content\"><a href=\"https://technitium.com\" target=\"_blank\">Technitium</a> | <a href=\"http://blog.technitium.com\" target=\"_blank\">Blog</a> | <a href=\"https://github.com/TechnitiumSoftware\" target=\"_blank\"><i class=\"fa fa-github\"></i>&nbsp;GitHub</a> | <a href=\"https://technitium.com/aboutus.html\" target=\"_blank\">About</a></div>");
});

function login() {

    var btn = $("#btnLogin").button('loading');;

    var username = $("#txtUser").val();
    var password = $("#txtPass").val();

    if ((username === null) || (username === "")) {
        showAlert("warning", "Missing!", "Please enter username.");
        btn.button('reset');
        return false;
    }

    if ((password === null) || (password === "")) {
        showAlert("warning", "Missing!", "Please enter password.");
        btn.button('reset');
        return false;
    }

    var apiUrl = "/api/login?user=" + username + "&pass=" + password;

    $.ajax({
        type: "GET",
        url: apiUrl,
        dataType: 'json',
        cache: false,
        success: function (responseJSON, status, jqXHR) {

            switch (responseJSON.status) {
                case "ok":
                    token = responseJSON.token;
                    hidePageLogin();
                    showUserMenu(username);
                    showPageMain();
                    break;

                case "error":
                    showAlert("danger", "Error!", responseJSON.errorMessage);
                    break;

                default:
                    showAlert("danger", "Error!", "Invalid status code was received.");
                    break;
            }

            btn.button('reset');
        },
        error: function (jqXHR, textStatus, errorThrown) {
            showAlert("danger", "Error!", jqXHR.status + " " + jqXHR.statusText);
            btn.button('reset');
        }
    });

    return false;
}

function logout() {

    var apiUrl = "/api/logout?token=" + token;

    $.ajax({
        type: "GET",
        url: apiUrl,
        dataType: 'json',
        cache: false,
        success: function (responseJSON, status, jqXHR) {

            switch (responseJSON.status) {
                case "ok":
                    token = null;
                    hidePageMain()
                    hideUserMenu();
                    showPageLogin();
                    break;

                case "error":
                    showAlert("danger", "Error!", responseJSON.errorMessage);
                    break;

                default:
                    showAlert("danger", "Error!", "Invalid status code was received.");
                    break;
            }
        },
        error: function (jqXHR, textStatus, errorThrown) {
            showAlert("danger", "Error!", jqXHR.status + " " + jqXHR.statusText);
        }
    });

    return false;
}

function showAlert(type, title, message) {
    var alertHTML = "<div class=\"alert alert-" + type + "\" role=\"alert\">\
    <button type=\"button\" class=\"close\" data-dismiss=\"alert\">&times;</button>\
    <strong>" + title + "</strong>&nbsp;" + message + "\
    </div>";

    var divAlert = $(".AlertPlaceholder");

    divAlert.html(alertHTML);
    divAlert.show();

    if (type === "success") {
        setTimeout(function () {
            hideAlert();
        }, 5000);
    }

    return true;
}

function hideAlert() {
    $(".AlertPlaceholder").hide();
}

function showPageLogin() {
    $(".AlertPlaceholder").hide();
    $("#txtUser").val("");
    $("#txtPass").val("");
    $("#pageLogin").show();
}

function hidePageLogin() {
    $("#pageLogin").hide();
}

function showUserMenu(username) {
    $("#mnuUserDisplayName").html(username);
    $("#mnuUser").show();
}

function hideUserMenu() {
    $("#mnuUser").hide();
}

function showPageMain() {
    $("#pageMain").show();
}

function hidePageMain() {
    $("#pageMain").hide();
}