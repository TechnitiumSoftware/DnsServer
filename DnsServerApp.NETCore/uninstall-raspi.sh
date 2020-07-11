#!/bin/sh

aspnetcoreDir="/opt/dotnet"
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
	else
		rm /etc/supervisor/conf.d/dns.conf >/dev/null 2>&1
		service supervisor restart >/dev/null 2>&1
	fi

	rm -rf $dnsDir >/dev/null 2>&1

	if [ -d $aspnetcoreDir ]
	then
		echo "Uninstalling .NET Core Runtime..."
		rm /usr/bin/dotnet >/dev/null 2>&1
		rm -rf $aspnetcoreDir >/dev/null 2>&1
	fi
fi

echo ""
echo "Thank you for using Technitium DNS Server!"
