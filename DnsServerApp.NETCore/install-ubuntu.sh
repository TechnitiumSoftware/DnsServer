#!/bin/sh

aspnetcoreDir="/opt/dotnet"
aspnetcoreTar="/opt/dotnet/aspnetcore-runtime-2.2.0-linux-x64.tar.gz"
aspnetcoreUrl="https://download.visualstudio.microsoft.com/download/pr/69ee3993-54fe-4687-9388-25b1e0c888fb/df2ba0637e68f6e8ee212a38756a4002/aspnetcore-runtime-2.2.0-linux-x64.tar.gz"

dnsDir="/etc/dns"
dnsTar="/etc/dns/DnsServerPortable.tar.gz"
dnsUrl="https://technitium.com/download/dns/DnsServerPortable.tar.gz"

mkdir -p $dnsDir
installLog="$dnsDir/install.log"
echo "" > $installLog

echo ""
echo "==============================="
echo "Technitium DNS Server Installer"
echo "==============================="

if [ ! -f /etc/dns/DnsServerApp.dll ]
then
	echo ""
	echo "Installing dependencies..."

	until apt-get -y update &>> $installLog && apt-get -y install libunwind8 icu-devtools apt-transport-https &>> $installLog
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
fi

echo ""
echo "Downloading Technitium DNS Server..."

if wget -q "$dnsUrl" -O $dnsTar
then
	if [ -f /etc/dns/DnsServerApp.dll ]
	then
		echo "Updating Technitium DNS Server..."
	else
		echo "Installing Technitium DNS Server..."
	fi
	
	tar -zxf $dnsTar -C $dnsDir
	
	if [ "$(ps --no-headers -o comm 1 | tr -d '\n')" = "systemd" ] 
	then
		if [ -f /etc/systemd/system/dns.service ]
		then
			echo "Restarting systemd service..."
			systemctl restart dns.service &>> $installLog
		else
			echo "Configuring systemd service..."
			cp $dnsDir/systemd.service /etc/systemd/system/dns.service
			systemctl enable dns.service &>> $installLog
			systemctl start dns.service &>> $installLog
		fi
	else
		if [ -f /etc/supervisor/conf.d/dns.conf ]
		then
			echo "Restarting supervisor service..."
			service supervisor restart &>> $installLog
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
	fi
	
	echo ""
	echo "Technitium DNS Server was installed succesfully!"
	echo "Open http://$(hostname):5380/ to access the web console."
else
	echo ""
	echo "Failed to download Technitium DNS Server from: $dnsUrl"
	exit 1
fi
