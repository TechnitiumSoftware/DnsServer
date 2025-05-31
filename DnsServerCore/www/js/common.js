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

function htmlEncode(value) {
    return $('<div/>').text(value).html().replace(/"/g, "&quot;");
}

function htmlDecode(value) {
    return $('<div/>').html(value).text();
}

function HTTPRequest(url, method, data, isTextResponse, success, error, invalidToken, twoFactorAuthRequired, objAlertPlaceholder, objLoaderPlaceholder, processData, contentType, dontHideAlert, showInnerError) {
    var finalUrl;

    if ((url != null) && (url.url != null))
        finalUrl = arguments[0].url;
    else
        finalUrl = url;

    if (method == null)
        method = arguments[0].method;

    if (method == null)
        method = "GET";

    if (data == null) {
        if (arguments[0].data == null)
            data = "";
        else
            data = arguments[0].data;
    }

    if (isTextResponse == null)
        isTextResponse = arguments[0].isTextResponse;

    if (isTextResponse == null)
        isTextResponse = false;

    var dataType = isTextResponse ? null : "json";

    if (success == null)
        success = arguments[0].success;

    var async = success != null;

    if (error == null)
        error = arguments[0].error;

    if (invalidToken == null)
        invalidToken = arguments[0].invalidToken;

    if (twoFactorAuthRequired == null)
        twoFactorAuthRequired = arguments[0].twoFactorAuthRequired;

    if (objAlertPlaceholder == null)
        objAlertPlaceholder = arguments[0].objAlertPlaceholder;

    if (dontHideAlert == null)
        dontHideAlert = arguments[0].dontHideAlert;

    if ((dontHideAlert == null) || !dontHideAlert)
        hideAlert(objAlertPlaceholder);

    if (showInnerError == null)
        showInnerError = arguments[0].showInnerError;

    if (showInnerError == null)
        showInnerError = false;

    if (objLoaderPlaceholder == null)
        objLoaderPlaceholder = arguments[0].objLoaderPlaceholder;

    if (processData == null)
        processData = arguments[0].processData;

    if (contentType == null)
        contentType = arguments[0].contentType;

    if (objLoaderPlaceholder != null)
        objLoaderPlaceholder.html("<div style='width: 64px; height: inherit; margin: auto;'><div style='height: inherit; display: table-cell; vertical-align: middle;'><img src='img/loader.gif'/></div></div>");

    var successFlag = false;

    $.ajax({
        type: method,
        url: finalUrl,
        data: data,
        dataType: dataType,
        async: async,
        cache: false,
        processData: processData,
        contentType: contentType,
        success: function (response, status, jqXHR) {
            if (objLoaderPlaceholder != null)
                objLoaderPlaceholder.html("");

            if (isTextResponse) {
                if (success == null)
                    successFlag = true;
                else
                    success(response);
            }
            else {
                switch (response.status) {
                    case "ok":
                        if (success == null)
                            successFlag = true;
                        else
                            success(response);

                        break;

                    case "invalid-token":
                        if (invalidToken != null)
                            invalidToken();
                        else {
                            showAlert("danger", "Error!", response.errorMessage + (showInnerError && (response.innerErrorMessage != null) ? " " + response.innerErrorMessage : ""), objAlertPlaceholder);

                            if (error != null)
                                error();
                            else
                                window.location = "/";
                        }
                        break;

                    case "2fa-required":
                        if (twoFactorAuthRequired != null) {
                            twoFactorAuthRequired();
                        }
                        else {
                            showAlert("danger", "Error!", response.errorMessage + (showInnerError && (response.innerErrorMessage != null) ? " " + response.innerErrorMessage : ""), objAlertPlaceholder);

                            if (error != null)
                                error();
                        }

                        break;

                    case "error":
                        showAlert("danger", "Error!", response.errorMessage + (showInnerError && (response.innerErrorMessage != null) ? " " + response.innerErrorMessage : ""), objAlertPlaceholder);

                        if (error != null)
                            error();

                        break;

                    default:
                        showAlert("danger", "Invalid Response!", "Server returned invalid response status: " + response.status, objAlertPlaceholder);

                        if (error != null)
                            error();

                        break;
                }
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
}

function hideAlert(objAlertPlaceholder) {
    if (objAlertPlaceholder == null)
        objAlertPlaceholder = $(".AlertPlaceholder");

    objAlertPlaceholder.html("");
}

function sortTable(tableId, n) {
    var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
    table = document.getElementById(tableId);
    switching = true;
    // Set the sorting direction to ascending:
    dir = "asc";
    /* Make a loop that will continue until
    no switching has been done: */
    while (switching) {
        // Start by saying: no switching is done:
        switching = false;
        rows = table.rows;
        /* Loop through all table rows */
        for (i = 0; i < (rows.length - 1); i++) {
            // Start by saying there should be no switching:
            shouldSwitch = false;
            /* Get the two elements you want to compare,
            one from current row and one from the next: */
            x = rows[i].getElementsByTagName("TD")[n];
            y = rows[i + 1].getElementsByTagName("TD")[n];
            /* Check if the two rows should switch place,
            based on the direction, asc or desc: */
            if (dir == "asc") {
                if (x.innerText.toLowerCase() > y.innerText.toLowerCase()) {
                    // If so, mark as a switch and break the loop:
                    shouldSwitch = true;
                    break;
                }
            } else if (dir == "desc") {
                if (x.innerText.toLowerCase() < y.innerText.toLowerCase()) {
                    // If so, mark as a switch and break the loop:
                    shouldSwitch = true;
                    break;
                }
            }
        }
        if (shouldSwitch) {
            /* If a switch has been marked, make the switch
            and mark that a switch has been done: */
            rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
            switching = true;
            // Each time a switch is done, increase this count by 1:
            switchcount++;
        } else {
            /* If no switching has been done AND the direction is "asc",
            set the direction to "desc" and run the while loop again. */
            if (switchcount == 0 && dir == "asc") {
                dir = "desc";
                switching = true;
            }
        }
    }
}

function serializeTableData(table, columns, objAlertPlaceholder) {
    var data = table.find('input:text, :input[type="number"], input:checkbox, input:hidden, select');
    var output = "";

    for (var i = 0; i < data.length; i += columns) {
        if (i > 0)
            output += "|";

        for (var j = 0; j < columns; j++) {
            if (j > 0)
                output += "|";

            var cell = $(data[i + j]);

            var cellValue;

            if (cell.attr("type") == "checkbox") {
                cellValue = cell.prop("checked").toString();
            }
            else {
                cellValue = cell.val();

                var optional = (cell.attr("data-optional") === "true");

                if ((cellValue === "") && !optional) {
                    showAlert("warning", "Missing!", "Please enter a valid value in the text field in focus.", objAlertPlaceholder);
                    cell.focus();
                    return false;
                }

                if (cellValue.includes("|")) {
                    showAlert("warning", "Invalid Character!", "Please edit the value in the text field in focus to remove '|' character.", objAlertPlaceholder);
                    cell.focus();
                    return false;
                }
            }

            output += htmlDecode(cellValue);
        }
    }

    return output;
}

function cleanTextList(text) {
    text = text.replace(/\n/g, ",");

    while (text.indexOf(",,") !== -1) {
        text = text.replace(/,,/g, ",");
    }

    if (text.startsWith(","))
        text = text.substr(1);

    if (text.endsWith(","))
        text = text.substr(0, text.length - 1);

    return text;
}
