/*
Technitium DNS Server
Copyright (C) 2018  Shreyas Zare (shreyas@technitium.com)

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

function htmlEncode(value) {
    return $('<div/>').text(value).html();
}

function htmlDecode(value) {
    return $('<div/>').html(value).text();
}

function HTTPRequest(url, data, success, error, invalidToken, objAlertPlaceholder, objLoaderPlaceholder, dataIsFormData, dataContentType, dontHideAlert) {

    var async = false;
    var finalUrl;

    finalUrl = arguments[0].url;

    if (data == null)
        if (arguments[0].data == null)
            data = "";
        else
            data = arguments[0].data;

    if (success != null)
        async = true;
    else
        if (arguments[0].success != null) {
            async = true;
            success = arguments[0].success;
        }

    if (error == null)
        error = arguments[0].error;

    if (invalidToken == null)
        invalidToken = arguments[0].invalidToken;

    if (objAlertPlaceholder == null)
        objAlertPlaceholder = arguments[0].objAlertPlaceholder;

    if (dontHideAlert == null)
        dontHideAlert = arguments[0].dontHideAlert;

    if ((dontHideAlert == null) || !dontHideAlert)
        hideAlert(objAlertPlaceholder);

    if (objLoaderPlaceholder == null)
        objLoaderPlaceholder = arguments[0].objLoaderPlaceholder;

    if (dataIsFormData == null)
        dataIsFormData = arguments[0].dataIsFormData;

    if (dataContentType == null)
        dataContentType = arguments[0].dataContentType;

    if (objLoaderPlaceholder != null)
        objLoaderPlaceholder.html("<div style='width: 64px; height: inherit; margin: auto;'><div style='height: inherit; display: table-cell; vertical-align: middle;'><img src='/img/loader.gif'/></div></div>");

    var successFlag = false;
    var processData;

    if (dataIsFormData != null) {
        if (dataIsFormData == true) {
            processData = false;
            dataContentType = false;
        }
    }

    $.ajax({
        type: "POST",
        url: finalUrl,
        data: data,
        dataType: "json",
        async: async,
        cache: false,
        processData: processData,
        contentType: dataContentType,
        success: function (responseJson, status, jqXHR) {

            if (objLoaderPlaceholder != null)
                objLoaderPlaceholder.html("");

            switch (responseJson.status) {
                case "ok":
                    if (success == null)
                        successFlag = true;
                    else
                        success(responseJson);

                    break;

                case "invalid-token":
                    if (invalidToken != null)
                        invalidToken();
                    else if (error != null)
                        error();
                    else
                        window.location = "/";

                    break;

                case "error":
                    showAlert("danger", "Error!", responseJson.errorMessage, objAlertPlaceholder);

                    if (error != null)
                        error();

                    break;

                default:
                    showAlert("danger", "Invalid Response!", "Server returned invalid response status: " + responseJson.status, objAlertPlaceholder);

                    if (error != null)
                        error();

                    break;
            }

        },
        error: function (jqXHR, textStatus, errorThrown) {

            if (objLoaderPlaceholder != null)
                objLoaderPlaceholder.html("");

            if (error != null)
                error();

            var msg;

            if ((textStatus === "error") && (errorThrown === ""))
                msg = "Unable to connect to the server. Please try again."
            else
                msg = textStatus + " - " + errorThrown;

            showAlert("danger", "Error!", msg, objAlertPlaceholder);
        }
    });

    return successFlag;
}

function HTTPGetFileRequest(url, success, error, objAlertPlaceholder, objLoaderPlaceholder, dontHideAlert) {

    var async = false;
    var finalUrl;

    finalUrl = arguments[0].url;

    if (success != null)
        async = true;
    else
        if (arguments[0].success != null) {
            async = true;
            success = arguments[0].success;
        }

    if (error == null)
        error = arguments[0].error;

    if (objAlertPlaceholder == null)
        objAlertPlaceholder = arguments[0].objAlertPlaceholder;

    if (dontHideAlert == null)
        dontHideAlert = arguments[0].dontHideAlert;

    if ((dontHideAlert == null) || !dontHideAlert)
        hideAlert(objAlertPlaceholder);

    if (objLoaderPlaceholder == null)
        objLoaderPlaceholder = arguments[0].objLoaderPlaceholder;

    if (objLoaderPlaceholder != null)
        objLoaderPlaceholder.html("<div style='width: 64px; height: inherit; margin: auto;'><div style='height: inherit; display: table-cell; vertical-align: middle;'><img src='/img/loader.gif'/></div></div>");

    var successFlag = false;

    $.ajax({
        type: "GET",
        url: finalUrl,
        async: async,
        cache: false,
        success: function (response, status, jqXHR) {

            if (objLoaderPlaceholder != null)
                objLoaderPlaceholder.html("");

            if (success == null)
                successFlag = true;
            else
                success(response);
        },
        error: function (jqXHR, textStatus, errorThrown) {

            if (objLoaderPlaceholder != null)
                objLoaderPlaceholder.html("");

            if (error != null)
                error();

            var msg;

            if ((textStatus === "error") && (errorThrown === ""))
                msg = "Unable to connect to the server. Please try again."
            else
                msg = textStatus + " - " + errorThrown;

            showAlert("danger", "Error!", msg, objAlertPlaceholder);
        }
    });

    return successFlag;
}

function showAlert(type, title, message, objAlertPlaceholder) {
    var alertHTML = "<div class=\"alert alert-" + type + "\">\
    <button type=\"button\" class=\"close\" data-dismiss=\"alert\">&times;</button>\
    <strong>" + title + "</strong>&nbsp;" + htmlEncode(message) + "\
    </div>";

    if (objAlertPlaceholder == null)
        objAlertPlaceholder = $(".AlertPlaceholder");

    objAlertPlaceholder.html(alertHTML);

    if (type == "success") {
        setTimeout(function () {
            hideAlert(objAlertPlaceholder);
        }, 5000);
    }

    return true;
}

function hideAlert(objAlertPlaceholder) {
    if (objAlertPlaceholder == null)
        objAlertPlaceholder = $(".AlertPlaceholder");

    objAlertPlaceholder.html("");
}
