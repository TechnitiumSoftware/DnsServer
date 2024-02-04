FROM mcr.microsoft.com/dotnet/aspnet:8.0
LABEL product="Technitium DNS Server"
LABEL vendor="Technitium"
LABEL email="support@technitium.com"
LABEL project_url="https://technitium.com/dns/"
LABEL github_url="https://github.com/TechnitiumSoftware/DnsServer"

WORKDIR /opt/technitium/dns/

RUN apt update; apt install curl -y; \
curl https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb --output packages-microsoft-prod.deb; \
dpkg -i packages-microsoft-prod.deb; \
rm packages-microsoft-prod.deb

RUN apt update; apt install dnsutils libmsquic -y; apt clean -y;

COPY ./DnsServerApp/bin/Release/publish/ .

EXPOSE 5380/tcp
EXPOSE 53443/tcp
EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 853/udp
EXPOSE 853/tcp
EXPOSE 443/udp
EXPOSE 443/tcp
EXPOSE 80/tcp
EXPOSE 8053/tcp
EXPOSE 67/udp

VOLUME ["/etc/dns"]

STOPSIGNAL SIGINT

ENTRYPOINT ["/usr/bin/dotnet", "/opt/technitium/dns/DnsServerApp.dll"]
CMD ["/etc/dns"]
