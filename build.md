# Build Instructions

## Debug Builds

### Windows or Linux

1. Clone the repository and initialize the submodule.

```
git clone https://github.com/TechnitiumSoftware/DnsServer.git
cd DnsServer
git submodule update --init --recursive
```

2. Open `DnsServer.sln` in Visual Studio (Windows) or build with `dotnet` on Linux. Select **Debug** and build.
   The TechnitiumLibrary source is built automatically as part of the solution.

---

## Windows Publishing

To create the Technitium DNS Server Windows Setup, install **Visual Studio 2022** and **Inno Setup**.

1. Open `DnsServer.sln`, select **Release**, and build the solution.

2. Publish the following projects to `DnsServer\DnsServerWindowsSetup\publish`:

   * `DnsServerSystemTrayApp`
   * `DnsServerWindowsService`

3. Open `DnsServerWindowsSetup\DnsServerSetup.iss` in Inno Setup and compile it to generate the installer.

---

## Linux Publishing

### 1. Install prerequisites

```
sudo apt update
sudo apt install curl git -y
```

### 2. Install ASP.NET Core SDK

Follow Microsoft’s distribution-specific instructions.

### 3. Install ASP.NET Core 9 SDK and optional QUIC support

```
sudo apt install dotnet-sdk-9.0 libmsquic -y
```

### 4. Clone repository and initialize submodule

```
git clone --depth 1 https://github.com/TechnitiumSoftware/DnsServer.git DnsServer
cd DnsServer
git submodule update --init --recursive
```

### 5. Publish the DNS server

```
dotnet publish DnsServerApp/DnsServerApp.csproj -c Release
```

### 6. Install as a systemd service (skip if using Docker)

```
sudo mkdir -p /opt/technitium/dns
sudo cp -r DnsServerApp/bin/Release/publish/* /opt/technitium/dns
sudo cp /opt/technitium/dns/systemd.service /etc/systemd/system/dns.service
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
sudo systemctl enable dns.service
sudo systemctl start dns.service
sudo rm /etc/resolv.conf
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
```

### 7. Build a Docker image (skip if using systemd)

```
cd DnsServer
sudo docker build -t technitium/dns-server:latest .
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
sudo docker compose up -d
```

### 8. Access the web console

Open:

```
http://<server-ip>:5380/
```

Set a login password to complete setup.
