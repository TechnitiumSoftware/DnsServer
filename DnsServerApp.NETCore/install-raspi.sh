#!/bin/sh

aspnetcoreDir="/opt/dotnet"
aspnetcoreTar="/opt/dotnet/aspnetcore-runtime-2.2.0-linux-arm.tar.gz"
aspnetcoreUrl="https://download.visualstudio.microsoft.com/download/pr/860e937d-aa99-4047-b957-63b4cba047de/da5ed8a5e7c1ac3b4f3d59469789adac/aspnetcore-runtime-2.2.0-linux-arm.tar.gz"

dnsDir="/etc/dns"
dnsTar="/etc/dns/DnsServerPortable.tar.gz"
dnsUrl="https://technitium.com/download/dns/DnsServerPortable.tar.gz"

mkdir -p $dnsDir
installLog="$dnsDir/install.log"

echo ""
echo "==============================="
echo "Technitium DNS Server Installer"
echo "==============================="
echo ""
echo "Installing dependencies..."

until apt-get -y update &>> $installLog && apt-get -y install curl libunwind8 gettext apt-transport-https &>> $installLog
do
	echo "Trying again.."
	sleep 2
done

echo ""

if [ ! -f /usr/bin/dotnet ]
then
	echo "Downloading .NET Core Runtime..."
	
	mkdir -p $aspnetcoreDir
	
	if wget -q "$aspnetcoreUrl" -O $aspnetcoreTar
	then
		echo "Installing .NET Core Runtime..."
		tar -zxf $aspnetcoreTar -C $aspnetcoreDir
		ln -s $aspnetcoreDir/dotnet /usr/bin
		echo ".NET Core Runtime was installed succesfully."
	else
		echo "Failed to download .NET Core Runtime from: $aspnetcoreUrl"
		exit 1
	fi
else
	echo ".NET Core Runtime was found installed."
fi

echo ""
echo "Downloading Technitium DNS Server..."

if wget -q "$dnsUrl" -O $dnsTar
then
	echo "Installing Technitium DNS Server..."
	tar -zxf $dnsTar -C $dnsDir
	
	if [ "$(ps --no-headers -o comm 1 | tr -d '\n')" = "systemd" ] 
	then
		echo "Configuring systemd service..."
		cp $dnsDir/systemd.service /etc/systemd/system/dns.service
		systemctl enable dns.service &>> $installLog
		systemctl start dns.service &>> $installLog
	else
		echo "Installing supervisor..."
		
		until apt-get -y install supervisor &>> $installLog
		do
			echo "Trying again.."
			sleep 2
		done
		
		echo "Configuring supervisor service..."
		cp $dnsDir/supervisor.conf /etc/supervisor/conf.d/dns.conf
		service supervisor restart &>> $installLog
	fi
	
	echo ""
	echo "Technitium DNS Server was installed succesfully!"
	echo "Open http://$(hostname):5380/ to access the web console."
else
	echo ""
	echo "Failed to download Technitium DNS Server from: $dnsUrl"
	exit 1
fi
