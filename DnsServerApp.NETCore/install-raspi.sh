#!/bin/sh

aspnetcoreDir="/opt/dotnet"
aspnetcoreTestDir="/opt/dotnet/shared/Microsoft.NETCore.App/2.2.5/"
aspnetcoreTar="/opt/dotnet/aspnetcore-runtime-2.2.5-linux-arm.tar.gz"
aspnetcoreUrl="https://download.visualstudio.microsoft.com/download/pr/cd6635b9-f6f8-4c2d-beda-2e381fe39586/740973b83c199bf863a51c83a2432151/aspnetcore-runtime-2.2.5-linux-arm.tar.gz"

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

if [ -d "$aspnetcoreTestDir" ] && [ -f "/usr/bin/dotnet" ]
then
	echo ".NET Core Runtime was found installed."
else
	echo "Installing dependencies..."

	until apt-get -y update >> $installLog 2>&1 && apt-get -y install curl libunwind8 gettext apt-transport-https >> $installLog 2>&1
	do
		echo "Trying again.."
		sleep 2
	done

	echo ""
	echo "Downloading .NET Core Runtime..."
	
	mkdir -p $aspnetcoreDir
	
	if wget -q "$aspnetcoreUrl" -O $aspnetcoreTar
	then
		echo "Installing .NET Core Runtime..."
		tar -zxf $aspnetcoreTar -C $aspnetcoreDir >> $installLog 2>&1

		if [ ! -f "/usr/bin/dotnet" ]
		then
			ln -s $aspnetcoreDir/dotnet /usr/bin
		fi

		echo ".NET Core Runtime was installed succesfully."
	else
		echo "Failed to download .NET Core Runtime from: $aspnetcoreUrl"
		exit 1
	fi
fi

echo ""
echo "Downloading Technitium DNS Server..."

if wget -q "$dnsUrl" -O $dnsTar
then
	if [ -f "/etc/dns/DnsServerApp.dll" ]
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
			systemctl start dns.service >> $installLog 2>&1
		fi
	else
		if [ -f "/etc/supervisor/conf.d/dns.conf" ]
		then
			echo "Restarting supervisor service..."
			service supervisor restart >> $installLog 2>&1
		else
			echo "Installing supervisor..."
			
			until apt-get -y install supervisor >> $installLog 2>&1
			do
				echo "Trying again.."
				sleep 2
			done
			
			echo "Configuring supervisor service..."
			cp $dnsDir/supervisor.conf /etc/supervisor/conf.d/dns.conf
			service supervisor restart >> $installLog 2>&1
		fi
	fi
	
	echo ""
	echo "Technitium DNS Server was installed succesfully!"
	echo "Open http://$(hostname):5380/ to access the web console."
else
	echo ""
	echo "Failed to download Technitium DNS Server from: $dnsUrl"
	exit 1
fi
