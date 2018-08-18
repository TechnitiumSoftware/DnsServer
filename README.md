# DnsServer

Technitium DNS Server is an open source tool that can be used for self hosting a local DNS server for privacy & security or, used for experimentation/testing by software developers on their computer. It works out-of-the-box with no or minimal configuration and provides a user friendly web console accessible using any web browser.

Nobody really bothers about domain name resolution since it works automatically behind the scenes and is complex to understand. Most computer software use the operating system's DNS resolver that usually query the configured ISP's DNS server using UDP protocol. This way works well for most people but, your ISP can see and control what website you can visit even when the website employ HTTPS security. Not only that, some ISPs can redirect, block or inject content into websites you visit even when you use a different DNS provider like Google DNS or Cloudflare DNS. Having Technitium DNS Server configured to use DNS-over-TLS or DNS-over-HTTPS forwarders, these privacy & security issues can be mitigated very effectively.

Developers regularly use the hosts file for configuring an IP address for a domain under testing. However, using the hosts file is cumbersome at times and can only be used to resolve domain name to an IP address. With a fully configurable DNS server running on your local machine, you can configure not just simple A records (for IP address) but, also configure other types of records like CNAME or MX etc. This allow you to have more control and power when you want to do testing that simulates the exact configuration that you have running on production.

Applications of using a locally hosted DNS server is limited only by the user's imagination!

Website: https://technitium.com/dns/
