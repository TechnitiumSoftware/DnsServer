#!/bin/sh

cleanup() {
    # On Alpine Linux get rid of virtual packages installed in support for this script.
    # If none was installed, just fail silently
    if $alpineLinux; then
        apk del .deps > /dev/null 2>&1
    fi
}

trap cleanup INT TERM EXIT

dotnetDir="/opt/dotnet"
dotnetVersion="9.0"
dotnetRuntime="Microsoft.AspNetCore.App 9.0."
dotnetUrl="https://dot.net/v1/dotnet-install.sh"

if [ -d "/etc/dns/config" ]
then
    dnsDir="/etc/dns"
else
    dnsDir="/opt/technitium/dns"
fi

dnsConfig="/etc/dns"
dnsTar="$dnsDir/DnsServerPortable.tar.gz"
dnsUrl="https://download.technitium.com/dns/DnsServerPortable.tar.gz"

installLog="$dnsDir/install.log"

echo ""
echo "==============================="
echo "Technitium DNS Server Installer"
echo "==============================="
echo ""

mkdir -p $dnsDir
echo "" > $installLog

if command -v apk >/dev/null 2>&1
then
    # On Alpine Linux we need bash & curl to install dotnet
    alpineLinux=true
    apk update >> $installLog 2>&1
    deps=""
    # Check for bash
    if ! command -v bash >/dev/null 2>&1; then
        deps="$deps bash"
    fi
    # Check for curl
    if ! command -v curl >/dev/null 2>&1; then
        deps="$deps curl"
    fi
    # Install missing packages, if any
    if [ -n "$deps" ]; then
        echo "Installing packages needed for the installation: $deps"
        apk add --no-cache --virtual .deps $deps
    fi
else
    alpineLinux=false
fi

if dotnet --list-runtimes 2> /dev/null | grep -q "$dotnetRuntime"; 
then
    dotnetFound="yes"
else
    dotnetFound="no"
fi

if [ ! -d $dotnetDir ] && [ "$dotnetFound" = "yes" ]
then
    echo "ASP.NET Core Runtime is already installed."
else
    if [ -d $dotnetDir ] && [ "$dotnetFound" = "yes" ]
    then
        dotnetUpdate="yes"
        echo "Updating ASP.NET Core Runtime..."
    else
        dotnetUpdate="no"
        echo "Installing ASP.NET Core Runtime..."
    fi

    curl -sSL $dotnetUrl | bash /dev/stdin -c $dotnetVersion --runtime aspnetcore --no-path --install-dir $dotnetDir --verbose >> $installLog 2>&1

    # On Alpine Linux dotnet requires libstdc++
    if $alpineLinux; then
        echo "Installing ASP.NET Core Runtime dependencies..."
        apk add --no-cache libstdc++ >> $installLog 2>&1
    fi

    if [ ! -f "/usr/bin/dotnet" ]
    then
        ln -s $dotnetDir/dotnet /usr/bin >> $installLog 2>&1
    fi

    if dotnet --list-runtimes 2> /dev/null | grep -q "$dotnetRuntime"; 
    then
        if [ "$dotnetUpdate" = "yes" ]
        then
            echo "ASP.NET Core Runtime was updated successfully!"
        else
            echo "ASP.NET Core Runtime was installed successfully!"
        fi
    else
        echo "Failed to install ASP.NET Core Runtime. Please check '$installLog' for details."
        exit 1
    fi
fi

echo ""
echo "Downloading Technitium DNS Server..."

if ! curl -o $dnsTar --fail $dnsUrl >> $installLog 2>&1
then
    echo "Failed to download Technitium DNS Server from: $dnsUrl"
    echo "Please check '$installLog' for details."
    exit 1
fi

if [ -d $dnsConfig ]
then
    echo "Updating Technitium DNS Server..."
else
    echo "Installing Technitium DNS Server..."
fi

tar -zxf $dnsTar -C $dnsDir >> $installLog 2>&1

echo ""

if dotnet $dnsDir/DnsServerApp.dll --icu-test >> $installLog 2>&1
then
    echo "ICU package is already installed."
else
    echo "Checking for required ICU package..."

    if command -v apt-get >/dev/null 2>&1; then
        # Debian/Ubuntu based
        if ! dpkg -l | grep -q "libicu"; then
            echo "Installing required ICU package..."
            apt-get update >> $installLog 2>&1

            # Try to install the most common package name
            if apt-cache show libicu74 >/dev/null 2>&1; then
                echo "Installing libicu74 package..."
                apt-get install -y libicu74 >> $installLog 2>&1
            elif apt-cache show libicu72 >/dev/null 2>&1; then
                echo "Installing libicu72 package..."
                apt-get install -y libicu72 >> $installLog 2>&1
            elif apt-cache show libicu70 >/dev/null 2>&1; then
                echo "Installing libicu70 package..."
                apt-get install -y libicu70 >> $installLog 2>&1
            else
                # Fallback to a generic approach
                echo "No specific libicu package was found, trying generic installation..."
                apt-get install -y libicu* >> $installLog 2>&1
            fi
        fi
    elif command -v dnf >/dev/null 2>&1; then
        # Fedora/RHEL based
        if ! rpm -qa | grep -q "libicu"; then
            echo "Installing required ICU package..."
            dnf install -y libicu >> $installLog 2>&1
        fi
    elif command -v yum >/dev/null 2>&1; then
        # Older RHEL/CentOS systems
        if ! rpm -qa | grep -q "libicu"; then
            echo "Installing required ICU package..."
            yum install -y libicu >> $installLog 2>&1
        fi
    elif command -v zypper >/dev/null 2>&1; then
        # openSUSE based
        if ! rpm -qa | grep -q "libicu"; then
            echo "Installing required ICU package..."
            zypper install -y libicu >> $installLog 2>&1
        fi
    elif command -v pacman >/dev/null 2>&1; then
        # Arch based
        if ! pacman -Q | grep -q "icu"; then
            echo "Installing required ICU package..."
            pacman -S --noconfirm icu >> $installLog 2>&1
        fi
    elif command -v apk >/dev/null 2>&1; then
        # Alpine Linux
        if ! apk list --installed | grep -q "icu"; then
            echo "Installing required ICU package..."
            apk add --no-cache icu >> $installLog 2>&1
        fi
    else
        echo "Failed to install Technitium DNS Server: could not determine package manager to install ICU package. Please install ICU package manually and try again."
        echo "Please read the 'Missing ICU Package' section in this blog post to understand how to manually install the ICU package for your distro: https://blog.technitium.com/2017/11/running-dns-server-on-ubuntu-linux.html"
        exit 1
    fi

    #test again to confirm
    if dotnet $dnsDir/DnsServerApp.dll --icu-test >> $installLog 2>&1
    then
        echo "ICU package was installed successfully!"
    else
        echo "Failed to install Technitium DNS Server: failed to install ICU package. Please install ICU package manually and try again."
        echo "Please read the 'Missing ICU Package' section in this blog post to understand how to manually install the ICU package for your distro: https://blog.technitium.com/2017/11/running-dns-server-on-ubuntu-linux.html"
        exit 1
    fi
fi

echo ""

installed=false
if [ "$(ps -o comm 1 | grep -v COMMAND)" = "systemd" ] 
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
        echo -e "# Generated by Technitium DNS Server Installer\n\nnameserver 127.0.0.1" > /etc/resolv.conf 2>> $installLog
        
        if [ -f "/etc/NetworkManager/NetworkManager.conf" ]
        then
            echo -e "[main]\ndns=default" >> /etc/NetworkManager/NetworkManager.conf 2>> $installLog
        fi
    fi
    installed=true

elif [ -x "/sbin/rc-service" ]
then
    if [ -f "/etc/init.d/dns" ]
    then
        echo "Restarting OpenRC service..."
        rc-service dns stop >> $installLog 2>&1
        rc-service dns start >> $installLog 2>&1
    else
        echo "Configuring OpenRC service..."
        cp $dnsDir/openrc.service /etc/init.d/dns
        chmod +x /etc/init.d/dns
        rc-update add dns >> $installLog 2>&1
        rc-service dns start >> $installLog 2>&1

        rm /etc/resolv.conf >> $installLog 2>&1
        echo -e "# Generated by Technitium DNS Server Installer\n\nnameserver 127.0.0.1" > /etc/resolv.conf 2>> $installLog
    fi
    installed=true
fi

if ! $installed
then
    echo "Failed to install Technitium DNS Server: systemd or OpenRC were not detected."
    echo "Please read the 'Installing DNS Server Manually' section in this blog post to understand how to manually install the DNS server on your distro: https://blog.technitium.com/2017/11/running-dns-server-on-ubuntu-linux.html"
    exit 1
fi

echo ""
echo "Technitium DNS Server was installed successfully!"
echo "Open http://$(cat /proc/sys/kernel/hostname):5380/ to access the web console."
echo ""
echo "Donate! Make a contribution by becoming a Patron: https://www.patreon.com/technitium"
echo ""
