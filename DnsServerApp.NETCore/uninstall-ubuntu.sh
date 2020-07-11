#!/bin/sh

dnsDir="/etc/dns"

echo ""
echo "================================="
echo "Technitium DNS Server Uninstaller"
echo "================================="
echo ""

echo "Uninstalling Technitium DNS Server..."

if [ -d $dnsDir ]
then
	if [ "$(ps --no-headers -o comm 1 | tr -d '\n')" = "systemd" ] 
	then
		sudo systemctl disable dns.service >/dev/null 2>&1
		sudo systemctl stop dns.service >/dev/null 2>&1
		rm /etc/systemd/system/dns.service >/dev/null 2>&1

		systemctl enable systemd-resolved >/dev/null 2>&1
		systemctl start systemd-resolved >/dev/null 2>&1

		rm /etc/resolv.conf >/dev/null 2>&1
		ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf >/dev/null 2>&1
	else
		rm /etc/supervisor/conf.d/dns.conf >/dev/null 2>&1
		service supervisor restart >/dev/null 2>&1
	fi

	rm -rf $dnsDir >/dev/null 2>&1

	echo "Uninstalling .NET Core Runtime..."
	apt-get -y remove aspnetcore-runtime-3.1 dotnet-runtime-3.1 dotnet-host dotnet-hostfxr-3.1 dotnet-runtime-deps-3.1 >/dev/null 2>&1
fi

echo ""
echo "Thank you for using Technitium DNS Server!"
