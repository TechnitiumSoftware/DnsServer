# syntax=docker.io/docker/dockerfile:1

## This stage is only used to support preparing the runtime-image stage
FROM ubuntu:24.04 AS deps
RUN <<HEREDOC
  # Add the MS repo to install libmsquic (which also adds libnuma):
  apt update && apt install -y curl
  curl https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb --output packages-microsoft-prod.deb
  dpkg -i packages-microsoft-prod.deb
  rm packages-microsoft-prod.deb
  apt update && apt install -y libmsquic
  apt clean -y

  # Workaround for `COPY` semantics to preserve symlinks you must copy at the directory level:
  # https://github.com/moby/moby/issues/40449
  mkdir /runtime-deps
  mv /usr/lib/x86_64-linux-gnu/libmsquic.so* /runtime-deps
  mv /usr/lib/x86_64-linux-gnu/libnuma.so* /runtime-deps
HEREDOC


## Published image - No shell or package manager (only what is needed to run the service)
FROM mcr.microsoft.com/dotnet/aspnet:8.0-noble-chiseled AS runtime-image
COPY ./DnsServerApp/bin/Release/publish/ .
# DNS-over-QUIC support (libmsquic):
COPY --link --from=deps /runtime-deps/ /usr/lib/x86_64-linux-gnu/

# Graceful shutdown support:
STOPSIGNAL SIGINT

# `/etc/dns` is expected to exist:
WORKDIR /etc/dns
WORKDIR /

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
