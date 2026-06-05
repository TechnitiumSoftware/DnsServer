# syntax=docker.io/docker/dockerfile:1

# Build stage: clone and build TechnitiumLibrary, publish DnsServerApp
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build

RUN apt-get update \
  && apt-get install -y --no-install-recommends git ca-certificates wget \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Clone TechnitiumLibrary into the same parent folder as the DnsServer source
RUN git clone --depth 1 https://github.com/TechnitiumSoftware/TechnitiumLibrary.git /src/TechnitiumLibrary

# Copy the DnsServer repository into the image build context
COPY . /src/DnsServer

# Build required TechnitiumLibrary projects (matches build.md)
RUN dotnet build /src/TechnitiumLibrary/TechnitiumLibrary.ByteTree/TechnitiumLibrary.ByteTree.csproj -c Release \
 && dotnet build /src/TechnitiumLibrary/TechnitiumLibrary.Net/TechnitiumLibrary.Net.csproj -c Release \
 && dotnet build /src/TechnitiumLibrary/TechnitiumLibrary.Security.OTP/TechnitiumLibrary.Security.OTP.csproj -c Release

# Publish the DnsServerApp
RUN dotnet publish /src/DnsServer/DnsServerApp/DnsServerApp.csproj -c Release -o /publish


# Runtime stage: small runtime image with libmsquic and troubleshooting tools
FROM mcr.microsoft.com/dotnet/aspnet:10.0

# Add the MS repository so we can install `libmsquic` for DOQ/HTTP3 support
ADD --link https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb /
RUN dpkg -i packages-microsoft-prod.deb && rm packages-microsoft-prod.deb \
  && apt-get update \
  && apt-get install -y --no-install-recommends libmsquic dnsutils \
  && apt-get clean -y && rm -rf /var/lib/apt/lists/* \
  && mkdir -p /etc/dns

WORKDIR /opt/technitium/dns

# Copy published output from build stage
COPY --from=build /publish /opt/technitium/dns

ENTRYPOINT ["/usr/bin/dotnet", "/opt/technitium/dns/DnsServerApp.dll"]
CMD ["/etc/dns"]


## Only append image metadata below this line:
EXPOSE \
  # Standard DNS service
  53/udp 53/tcp      \
  # DNS-over-QUIC (UDP) + DNS-over-TLS (TCP)
  853/udp 853/tcp    \
  # DNS-over-HTTPS (UDP => HTTP/3) (TCP => HTTP/1.1 + HTTP/2)
  443/udp 443/tcp    \
  # DNS-over-HTTP (for when running behind a reverse-proxy that terminates TLS)
  80/tcp 8053/tcp    \
  # Technitium web console + API (HTTP / HTTPS)
  5380/tcp 53443/tcp \
  # DHCP
  67/udp

# https://specs.opencontainers.org/image-spec/annotations/
# https://github.com/opencontainers/image-spec/blob/main/annotations.md
LABEL org.opencontainers.image.title="Technitium DNS Server"
LABEL org.opencontainers.image.vendor="Technitium"
LABEL org.opencontainers.image.source="https://github.com/TechnitiumSoftware/DnsServer"
LABEL org.opencontainers.image.url="https://technitium.com/dns/"
LABEL org.opencontainers.image.authors="support@technitium.com"
