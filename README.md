<p align="center">
	<a href="https://technitium.com/dns/">
		<img src="https://technitium.com/img/logo.png" alt="Technitium DNS Server" /><br />
		<b>Technitium DNS Server</b>
	</a><br />
	<br />
	<b>Get a personal local DNS Server for privacy & security.</b><br />
	<b>Block Ads at DNS level!</b>
</p>
<p>
<img src="https://technitium.com/dns/ScreenShot1.png" alt="Technitium DNS Server" />
</p>

Technitium DNS Server is an open source tool that can be used for self hosting a local DNS server for privacy & security or, used for experimentation/testing by software developers on their computer. It works out-of-the-box with no or minimal configuration and provides a user friendly web console accessible using any web browser.

Nobody really bothers about domain name resolution since it works automatically behind the scenes and is complex to understand. Most computer software use the operating system's DNS resolver that usually query the configured ISP's DNS server using UDP protocol. This way works well for most people but, your ISP can see and control what website you can visit even when the website employ HTTPS security. Not only that, some ISPs can redirect, block or inject content into websites you visit even when you use a different DNS provider like Google DNS or Cloudflare DNS. Having Technitium DNS Server configured to use DNS-over-TLS or DNS-over-HTTPS forwarders, these privacy & security issues can be mitigated very effectively.

Developers regularly use the hosts file for configuring an IP address for a domain under testing. However, using the hosts file is cumbersome at times and can only be used to resolve domain name to an IP address. With a fully configurable DNS server running on your local machine, you can configure not just simple A records (for IP address) but, also configure other types of records like CNAME or MX etc. This allow you to have more control and power when you want to do testing that simulates the exact configuration that you have running on production.

Applications of using a locally hosted DNS server is limited only by the user's imagination!

# Features
- Works on Windows, Linux, macOS and Raspberry Pi.
- Installs in just a minute and works out-of-the-box with zero configuration.
- Block Ads using one or more block list URLs.
- Run [DNS-over-TLS](https://en.wikipedia.org/wiki/DNS_over_TLS) and [DNS-over-HTTPS](https://en.wikipedia.org/wiki/DNS_over_HTTPS) DNS service on your network.
- Use public DNS resolvers like Cloudflare, Google & Quad9 with [DNS-over-TLS](https://en.wikipedia.org/wiki/DNS_over_TLS) and [DNS-over-HTTPS](https://en.wikipedia.org/wiki/DNS_over_HTTPS) protocols as forwarders.
- Advance caching with features like serve stale, prefetching and auto prefetching.
- Supports working as an authoritative as well as a recursive DNS server.
- Host domain names on your own DNS server.
- Wildcard sub domain support.
- Enable/disable zones and records to allow testing with ease.
- Built-in DNS Client with option to import responses to local zone.
- Supports out-of-order DNS request processing for DNS-over-TCP and DNS-over-TLS protocols.
- Built-in DHCP Server that can work for multiple networks.
- IPv6 support in DNS server core.
- HTTP & SOCKS5 proxy support which can be configured to route DNS over [Tor Network](https://www.torproject.org/) or use Cloudflare's hidden DNS resolver.
- Web console portal for easy configuration using any web browser.
- Built-in system logging and query logging.
- Open source cross-platform .NET Core implementation hosted on GitHub.

# Installation
- **Windows**: [Download setup installer](https://download.technitium.com/dns/DnsServerSetup.zip) for easy installation.
- **Linux & Raspberry Pi**: Follow install instructions from [this blog post](https://blog.technitium.com/2017/11/running-dns-server-on-ubuntu-linux.html).
- **Cross-Platform**: [Download portable app](https://download.technitium.com/dns/DnsServerPortable.tar.gz) to run on any platform that has .NET Core installed.

# Help Topics
Read the latest [online help topics](https://go.technitium.com/?id=25) which contains the DNS Server user manual and covers frequently asked questions.

# Support
For support, send an email to support@technitium.com. For any issues, feedback, or feature request, create an issue on [GitHub](https://github.com/TechnitiumSoftware/DnsServer/issues).

# Become A Patron
Make contribution to Technitium by becoming a Patron and help making new software, updates, and features possible.

[Become a Patron now!](https://www.patreon.com/technitium)

# Blog Posts
- [Scott Hanselman: Exploring DNS with the .NET Core based Technitium DNS Server](https://www.hanselman.com/blog/ExploringDNSWithTheNETCoreBasedTechnitiumDNSServer.aspx) (April 2019)
- [Technitium Blog: Turn Raspberry Pi Into Network Wide DNS Server](https://blog.technitium.com/2019/01/turn-raspberry-pi-into-network-wide-dns.html) (Jan 2019)
- [Technitium Blog: Blocking Internet Ads Using DNS Sinkhole](https://blog.technitium.com/2018/10/blocking-internet-ads-using-dns-sinkhole.html) (Oct 2018)
- [Technitium Blog: Configuring DNS Server For Privacy & Security](https://blog.technitium.com/2018/06/configuring-dns-server-for-privacy.html) (June 2018)
- [Technitium Blog: Technitium DNS Server v1.3 Released!](https://blog.technitium.com/2018/06/technitium-dns-server-v13-released.html) (June 2018)
- [Technitium Blog: Running Technitium DNS Server on Ubuntu Linux](https://blog.technitium.com/2017/11/running-dns-server-on-ubuntu-linux.html) (Nov 2017)
- [Technitium Blog: Technitium DNS Server Released!](https://blog.technitium.com/2017/11/technitium-dns-server-released.html) (Nov 2017)




# Example hosting for hosting your own website
Besides all the amazing features, Technitium can also be used for (at least the following) 2 scenarios:

  0. You want to redirect website to a an ip of a different website, e.g. www.wastingTheTimeOfYourLife.com to www.qualitativeInformationEnhancingTheTimeOfYourAndOthersLife.com
  1. If you bought/aqcuired a domain and want to show your website on it by yourself.

So for example suppose you bought www.google.com and you have made a beautifull website (on your pc) that you want to show when people visit google.com:

 0. Install technitium dns server (or download the portable version)
 1. Run `DnsServerApp.exe`
 2. Open a browser and browse to the local host adress that the `DnsServerApp.exe` gives you. E.g. `http://desktop-234asfdn2:5380/`.
 3. Go to the tab: `Zones`.
 4. Click on `Add Zone`
	![1](./ExamplePictures/4a.png)
 5. and enter `google.com`
 
	![1](./ExamplePictures/4b.png)
 6. Then click on "Add record", 
	![1](./ExamplePictures/5.png)
 7. select Type:`A` and at the IP adress type the PUBLIC IP address of your pc. (The PUBLIC IP adress is what you see when you visit: www.whatsmyip.org, e.g. 202.202.12)
	![1](./ExamplePictures/6.png)
 8. Now you're already done, but it only works if people visit google.com and not `www.google.com`. So:
 9. Again, click "Add record"
 
	![1](./ExamplePictures/7a.png)
 10. at Name enter:`www`
 11. at Type select:`CNAME`
 12. at Domain Name type:`google.com`
 
	![1](./ExamplePictures/7b.png)
 13. Now Technitium/your DNS server forwards `www` to `google.com` and then redirects `google.com` to your ip, meaning people see your website :)
 
 You can now verify you indeed redirect `www.google.com` to your computer, to do so: 
 
 14. Get the public ip adress of your computer, (for this example I'll use 202.202.12).
 15. Open Powershell
 16. Type: nslookup www.google.com
 17. That should return the ip adress of google (veriy it does, by copying the adress it returns and entering it in your browser {at the time of writing it was `172.217.19.196`)).
 18. Now type: `nslookup www.google.com <your ip adress>`
 19. So in this example that would be:`nslookup www.google.com 202.202.12`
 
![1](./ExamplePictures/14.png)
 20. That should regurn the ip adress that you entered at step 6 (in steps 10 to 15 of this example it was `234.54.231.1)`.
 
![1](./ExamplePictures/15.png)
