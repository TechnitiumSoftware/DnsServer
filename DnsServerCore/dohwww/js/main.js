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

$(function () {
    var hostname = window.location.hostname;

    var dohLink = "https://" + hostname + "/dns-query";
    var dotLink = hostname;

    $("button.copyBtn[data-type='doh']").data("ip", dohLink);
    $("button.copyBtn[data-type='dot']").data("ip", dotLink);

    $(".lnkDoH").text(dohLink).attr("href", dohLink);
    $(".lnkDoHText").text(dohLink);

    $(".lnkDoT").text(dotLink).attr("href", "tls://" + dotLink);
    $(".lnkDoTText").text(dotLink);

    function updateDNSLinks(recordType, selector, textSelector, dataAttr) {
        $.ajax({
            ﻿/*url: "https://" + window.location.hostname + "/dns-query", (damn!)*/
            url: "https://cloudflare-dns.com/dns-query",
            data: {
                name: hostname,
                type: recordType
            },
            headers: {
                "Accept": "application/dns-json"
            },
            success: function (data) {
                if (data && data.Answer && data.Answer.length > 0) {
                    var ip = null;
                    for (var i = 0; i < data.Answer.length; i++) {
                        if ((recordType === "A" && data.Answer[i].type === 1) ||
                            (recordType === "AAAA" && data.Answer[i].type === 28)) {
                            ip = data.Answer[i].data;
                            break;
                        }
                    }

                    if (ip) {
                        $(selector).text(ip).attr("href", "dns://" + ip);
                        $(textSelector).text(ip);

                        $("button.copyBtn[data-type='" + dataAttr + "']").data("ip", ip);
                    }
                }
            },
            error: function () {
                $(selector).text("IP resolution failed").attr("href", "#");
                $(textSelector).text("IP resolution failed");
            }
        });
    }

    updateDNSLinks("A", ".lnkDNSv4", ".lnkDNSv4Text", "v4");
    updateDNSLinks("AAAA", ".lnkDNSv6", ".lnkDNSv6Text", "v6");

    $(document).on("click", "button.copyBtn", function () {
        var ip = $(this).data("ip");
        if (ip) {
            navigator.clipboard.writeText(ip).then(function () {
                $('<div class="alert alert-success copy-alert" style="position: fixed; top: 20px; right: 20px; z-index: 9999;">Copied: ' + ip + '</div>')
                    .appendTo('body')
                    .delay(1500)
                    .fadeOut(500, function () { $(this).remove(); });
            }, function () {
                alert("Copy failed");
            });
        }
    });

    var dohOverlay = $(".lnkDoHText").first().text().trim();
    $("#firefoxOverlay").text(dohOverlay);
});
