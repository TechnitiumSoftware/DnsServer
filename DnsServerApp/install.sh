#!/bin/sh

dotnetDir="/opt/dotnet"
dnsDir="/etc/dns"
dnsTar="/etc/dns/DnsServerPortable.tar.gz"
dnsUrl="https://download.technitium.com/dns/DnsServerPortable.tar.gz"

mkdir -p $dnsDir
installLog="$dnsDir/install.log"
echo "" > $installLog

echo ""
echo "==============================="
echo "Technitium DNS Server Installer"
echo "==============================="
echo ""
echo "Installing .NET 5 Runtime..."

curl -sSL https://dot.net/v1/dotnet-install.sh | bash /dev/stdin -c 5.0 --runtime dotnet --no-path --install-dir $dotnetDir --verbose >> $installLog 2>&1

if [ ! -f "/usr/bin/dotnet" ]
then
	ln -s $dotnetDir/dotnet /usr/bin >> $installLog 2>&1
fi

echo ""
echo "Downloading Technitium DNS Server..."

if curl -o $dnsTar --fail $dnsUrl >> $installLog 2>&1
then
	if [ -d "/etc/dns/" ]
	then
		echo "Updating Technitium DNS Server..."
	else
		echo "Installing Technitium DNS Server..."
	fi
	
	tar -zxf $dnsTar -C $dnsDir >> $installLog 2>&1
	
	if [ "$(ps --no-headers -o comm 1 | tr -d '\n')" = "systemd" ] 
	then
		if [ -f "/etc/systemd/system/dns.service" ]
		then
			echo "Restarting systemd service..."
			systemctl restart dns.service >> $installLog 2>&1
		else
			echo "Configuring systemd service..."
			cp $dnsDir/systemd.service /etc/systemd/system/dns.service
			systemctl enable dns.service >> $installLog 2>&1
			
			systemctl stop systemd-resolved >> $installLog 2>&1
			systemctl disable systemd-resolved >> $installLog 2>&1
			
			systemctl start dns.service >> $installLog 2>&1
			
			rm /etc/resolv.conf >> $installLog 2>&1
			echo "nameserver 127.0.0.1" > /etc/resolv.conf 2>> $installLog
			
			if [ -f "/etc/NetworkManager/NetworkManager.conf" ]
			then
				echo "[main]" >> /etc/NetworkManager/NetworkManager.conf
				echo "dns=default" >> /etc/NetworkManager/NetworkManager.conf
			fi
		fi
	
		echo ""
		echo "Technitium DNS Server was installed succesfully!"
		echo "Open http://$(hostname):5380/ to access the web console."
	else
		echo ""
		echo "Failed to install Technitium DNS Server: systemd was not detected."
	fi
else
	echo ""
	echo "Failed to download Technitium DNS Server from: $dnsUrl"
	exit 1
fi
