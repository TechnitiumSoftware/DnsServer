
function htmlEncode(value) {
    return $('<div/>').text(value).html();
}

function htmlDecode(value) {
    return $('<div/>').html(value).text();
}

function HTTPRequest(url, data, success, error, invalidToken, objAlertPlaceholder, objLoaderPlaceholder, dataIsFormData, dataContentType) {

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
                    if (error != null)
                        error();

                    showAlert("danger", "Error!", responseJson.errorMessage, objAlertPlaceholder);
                    break;

                default:
                    if (error != null)
                        error();

                    showAlert("danger", "Invalid Response! Server returned invalid response: ", responseJson.status, objAlertPlaceholder);
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

function showAlert(type, title, message, objAlertPlaceholder) {
    var alertHTML = "<div class=\"alert alert-" + type + "\">\
    <button type=\"button\" class=\"close\" data-dismiss=\"alert\">&times;</button>\
    <strong>" + title + "</strong>&nbsp;" + message + "\
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
