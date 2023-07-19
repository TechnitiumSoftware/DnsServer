# syntax=docker/dockerfile:1.5

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS builder

WORKDIR /src
RUN <<EOF bash
# Stop on first error
set -xe

git clone --depth 1 https://github.com/TechnitiumSoftware/TechnitiumLibrary.git TechnitiumLibrary
git clone --depth 1 https://github.com/TechnitiumSoftware/DnsServer.git DnsServer

dotnet build TechnitiumLibrary/TechnitiumLibrary.ByteTree/TechnitiumLibrary.ByteTree.csproj -c Release
dotnet build TechnitiumLibrary/TechnitiumLibrary.Net/TechnitiumLibrary.Net.csproj -c Release

dotnet publish DnsServer/DnsServerApp/DnsServerApp.csproj -c Release
EOF

FROM mcr.microsoft.com/dotnet/aspnet:7.0
LABEL product="Technitium DNS Server"
LABEL vendor="Technitium"
LABEL email="support@technitium.com"
LABEL project_url="https://technitium.com/dns/"
LABEL github_url="https://github.com/TechnitiumSoftware/DnsServer"


# Using build cache to speed up the build process
RUN rm -f /etc/apt/apt.conf.d/docker-clean; echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

WORKDIR /opt/technitium/dns/


RUN --mount=type=cache,target=/var/cache --mount=type=cache,target=/var/lib/apt <<EOF bash
set -xe

apt update
apt dist-upgrade -y --no-install-recommends
apt install curl -y --no-install-recommends

curl https://packages.microsoft.com/config/debian/11/packages-microsoft-prod.deb --output packages-microsoft-prod.deb
dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb

apt update
apt install -y --no-install-recommends libmsquic
apt autoremove -y

EOF


COPY --link --from=builder /src/DnsServer/DnsServerApp/bin/Release/publish/ .

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
