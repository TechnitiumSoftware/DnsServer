%global _enable_debug_package 0
%define debug_package %{nil}

Name:           technitium
Version:        14.3
Release:        1%{?dist}
Summary:        Technitium DNS Server

License:        GPL
URL:            https://technitium.com
Source0:        %{name}-%{version}.tar.xz

BuildArch:      x86_64
Requires:       aspnetcore-runtime-9.0
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
Technitium DNS Server is an open-source authoritative and recursive DNS server
that can be installed on Linux systems using .NET runtime.

%prep
#%setup -q -n %{name}-%{version}
%setup -q

%build
# Nothing to build

%install
rm -rf %{buildroot}

# Create directories
mkdir -p %{buildroot}/etc/technitium/dns

# Copy application files
cp -r * %{buildroot}/etc/technitium/dns/

# Create systemd directory
mkdir -p %{buildroot}/usr/lib/systemd/system

# Create systemd service file
cat > %{buildroot}/usr/lib/systemd/system/technitium.service <<EOF
[Unit]
Description=Technitium DNS Server
After=network.target

[Service]
WorkingDirectory=/etc/technitium/dns
ExecStart=/usr/bin/dotnet /etc/technitium/dns/DnsServerApp.dll /etc/dns
Restart=always
RestartSec=10
SyslogIdentifier=dns-server

[Install]
WantedBy=multi-user.target
EOF

%post
%systemd_post technitium.service

%preun
%systemd_preun technitium.service

%postun
%systemd_postun_with_restart technitium.service

%files
%dir /etc/technitium
%dir /etc/technitium/dns
/etc/technitium/dns/*
/usr/lib/systemd/system/technitium.service

%changelog
* Wed Mar 11 2026 Zakir Hossain <zakirpcs@gmail.com> 14.3-1
- Initial RPM build for Technitium DNS Server 14.3-1
