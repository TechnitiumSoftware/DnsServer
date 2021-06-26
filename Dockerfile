FROM mcr.microsoft.com/dotnet/runtime:5.0
LABEL product="Technitium DNS Server"
LABEL vendor="Technitium"
LABEL email="support@technitium.com"
LABEL project_url="https://technitium.com/dns/"
LABEL github_url="https://github.com/TechnitiumSoftware/DnsServer"

WORKDIR /etc/dns/

COPY ./DnsServerApp/bin/Release/publish/ .

EXPOSE 5380/tcp
EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 67/udp
EXPOSE 853/tcp
EXPOSE 443/tcp
EXPOSE 80/tcp

VOLUME ["/etc/dns/config"]

CMD ["/usr/bin/dotnet", "/etc/dns/DnsServerApp.dll"]
