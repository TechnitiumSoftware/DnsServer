import { AreaRow, Avisos, Block, Check, GroupRow, Help, Note, Plain, Pre, TextRow } from '../parts'
import type { PaneProps } from './tipos'

const PROXY_PROTOCOL = (
  <a href="https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt" target="_blank" rel="noreferrer">
    PROXY Protocol
  </a>
)

/*
Settings > Optional Protocols (index.html:1562-1768).

This is where upstream's inconsistency with `Enable DNS-over-HTTP/3` lives: on
load, `loadDnsSettings` disables it if `enableDnsOverHttps` is off
(main.js:1318), but no `click` handler ever re-evaluates it when `Enable
DNS-over-HTTPS` gets checked, so until the page is reloaded it stays off. Here
the rule is derived from state and therefore DOES update itself; it is the only
observable difference and it is noted in the phase's report.
*/
export function OptionalProtocols({ f, set, en }: PaneProps) {
  return (
    <>
      <Block title="Optional DNS Server Protocols">
        <GroupRow label="Optional DNS Server Protocols">
          <Check
            conmutador
            label="Enable EDNS Client Subnet (ECS) Source Address"
            checked={f.enableEDnsClientSubnetSourceAddress}
            onChange={(v) => set({ enableEDnsClientSubnetSourceAddress: v })}
            help={
              <>
                Enable this option to read the client's source IP address from the EDNS Client
                Subnet (ECS) option in the DNS requests coming via DNS-over-UDP or DNS-over-TCP
                protocols. This option allows a DNS proxy to pass the client's source IP address via
                ECS option to the DNS Server. It is mandatory to configure{' '}
                <b>Reverse Proxy Network ACL</b> below to allow requests coming from your DNS proxy
                server to work with this option.
              </>
            }
          />
          <Check
            conmutador
            label="Enable DNS-over-UDP-PROXY"
            checked={f.enableDnsOverUdpProxy}
            onChange={(v) => set({ enableDnsOverUdpProxy: v })}
            help={
              <>
                Enable this option to accept DNS-over-UDP-PROXY requests. It implements the{' '}
                {PROXY_PROTOCOL} for both version 1 &amp; 2 over UDP datagram. It is mandatory to
                configure <b>Reverse Proxy Network ACL</b> below to allow requests coming from your
                reverse proxy server.
              </>
            }
          />
          <Check
            conmutador
            label="Enable DNS-over-TCP-PROXY"
            checked={f.enableDnsOverTcpProxy}
            onChange={(v) => set({ enableDnsOverTcpProxy: v })}
            help={
              <>
                Enable this option to accept DNS-over-TCP-PROXY requests. It implements the{' '}
                {PROXY_PROTOCOL} for both version 1 &amp; 2 over TCP connection. It is mandatory to
                configure <b>Reverse Proxy Network ACL</b> below to allow requests coming from your
                reverse proxy server.
              </>
            }
          />
          <Check
            conmutador
            label="Enable DNS-over-HTTP"
            checked={f.enableDnsOverHttp}
            onChange={(v) => set({ enableDnsOverHttp: v })}
            help={
              <>
                Enable this option to accept DNS-over-HTTP requests. It must be used with a TLS
                terminating reverse proxy like nginx. It is mandatory to configure{' '}
                <b>Reverse Proxy Network ACL</b> below to allow requests coming from your reverse
                proxy server. Enabling this option also allows automatic TLS certificate renewal
                with HTTP challenge (webroot) for DNS-over-HTTPS service when DNS-over-HTTP port is
                set to 80.
              </>
            }
          />
          <Check
            conmutador
            label="Enable DNS-over-HTTP Unix Domain Sockets (UDS)"
            checked={f.enableDnsOverHttpUnixSocket}
            onChange={(v) => set({ enableDnsOverHttpUnixSocket: v })}
            help="Enable this option to accept DNS-over-HTTP requests over Unix Domain Sockets (UDS)."
          />
          <Check
            conmutador
            label="Enable DNS-over-HTTPS Unix Domain Sockets (UDS)"
            checked={f.enableDnsOverHttpsUnixSocket}
            onChange={(v) => set({ enableDnsOverHttpsUnixSocket: v })}
            help="Enable this option to accept DNS-over-HTTPS requests over Unix Domain Sockets (UDS)."
          />
          <Check
            conmutador
            label="Enable DNS-over-TLS"
            checked={f.enableDnsOverTls}
            onChange={(v) => set({ enableDnsOverTls: v })}
            help="Enable this option to accept DNS-over-TLS requests."
          />
          <Check
            conmutador
            label="Enable DNS-over-HTTPS"
            checked={f.enableDnsOverHttps}
            onChange={(v) => set({ enableDnsOverHttps: v })}
            help="Enable this option to accept DNS-over-HTTPS requests."
          />
          <Check
            conmutador
            label="Enable DNS-over-HTTP/3"
            checked={f.enableDnsOverHttp3}
            onChange={(v) => set({ enableDnsOverHttp3: v })}
            disabled={!en.enableDnsOverHttp3}
            help="Enable this option to accept DNS-over-HTTP/3 requests."
          />
          <Check
            conmutador
            label="Enable DNS-over-QUIC"
            checked={f.enableDnsOverQuic}
            onChange={(v) => set({ enableDnsOverQuic: v })}
            help="Enable this option to accept DNS-over-QUIC requests."
          />
        </GroupRow>

        <GroupRow label="DNS-over-HTTP(s) Option">
          <Check
            conmutador
            label="Enable Redirect To Help Page"
            checked={f.enableDnsOverHttpHelpRedirect}
            onChange={(v) => set({ enableDnsOverHttpHelpRedirect: v })}
            help={
              <>
                When this option is enabled, if a user visits the <code>/dns-query</code>{' '}
                DNS-over-HTTP(s) URL path using a web browser, the web browser will be redirected to{' '}
                <code>/</code> URL path to display the help page for the DNS-over-HTTP(s) service.
              </>
            }
          />
        </GroupRow>
      </Block>

      <Block title="Ports And Sockets">
        <TextRow
          label="DNS-over-UDP-PROXY Port"
          type="number"
          value={f.dnsOverUdpProxyPort}
          onChange={(v) => set({ dnsOverUdpProxyPort: v })}
          placeholder="port"
          suffix="(default 538)"
          disabled={!en.dnsOverUdpProxyPort}
          help="Specify the UDP port number for DNS-over-UDP-PROXY protocol."
        />
        <TextRow
          label="DNS-over-TCP-PROXY Port"
          type="number"
          value={f.dnsOverTcpProxyPort}
          onChange={(v) => set({ dnsOverTcpProxyPort: v })}
          placeholder="port"
          suffix="(default 538)"
          disabled={!en.dnsOverTcpProxyPort}
          help="Specify the TCP port number for DNS-over-TCP-PROXY protocol."
        />
        <TextRow
          label="DNS-over-HTTP Port"
          type="number"
          value={f.dnsOverHttpPort}
          onChange={(v) => set({ dnsOverHttpPort: v })}
          placeholder="port"
          suffix="(default 80)"
          disabled={!en.dnsOverHttpPort}
          help="Specify the TCP port number for DNS-over-HTTP protocol."
        />
        <TextRow
          label="DNS-over-HTTP UDS File Path"
          value={f.dnsOverHttpUnixSocket}
          onChange={(v) => set({ dnsOverHttpUnixSocket: v })}
          placeholder="/path/to/doh.sock"
          width="wide"
          disabled={!en.dnsOverHttpUnixSocket}
          help="Specify the Unix Domain Sockets (UDS) file path for DNS-over-HTTP protocol service. Ensure that the DNS Server has read+write permissions to the parent directory to be able to create the UDS file."
        />
        <TextRow
          label="DNS-over-HTTPS UDS File Path"
          value={f.dnsOverHttpsUnixSocket}
          onChange={(v) => set({ dnsOverHttpsUnixSocket: v })}
          placeholder="/path/to/dohs.sock"
          width="wide"
          disabled={!en.dnsOverHttpsUnixSocket}
          help="Specify the Unix Domain Sockets (UDS) file path for DNS-over-HTTPS protocol service. Ensure that the DNS Server has read+write permissions to the parent directory to be able to create the UDS file."
        />
        <TextRow
          label="DNS-over-TLS Port"
          type="number"
          value={f.dnsOverTlsPort}
          onChange={(v) => set({ dnsOverTlsPort: v })}
          placeholder="port"
          suffix="(default 853)"
          disabled={!en.dnsOverTlsPort}
          help="Specify the TCP port number for DNS-over-TLS protocol."
        />
        <TextRow
          label="DNS-over-HTTPS Port"
          type="number"
          value={f.dnsOverHttpsPort}
          onChange={(v) => set({ dnsOverHttpsPort: v })}
          placeholder="port"
          suffix="(default 443)"
          disabled={!en.dnsOverHttpsPort}
          help="Specify the TCP port number for DNS-over-HTTPS protocol."
        />
        <TextRow
          label="DNS-over-QUIC Port"
          type="number"
          value={f.dnsOverQuicPort}
          onChange={(v) => set({ dnsOverQuicPort: v })}
          placeholder="port"
          suffix="(default 853)"
          disabled={!en.dnsOverQuicPort}
          help="Specify the UDP port number for DNS-over-QUIC protocol."
        />
      </Block>

      <Block title="Reverse Proxy">
        <AreaRow
          label="Reverse Proxy Network ACL"
          value={f.dnsReverseProxyNetworkACL}
          onChange={(v) => set({ dnsReverseProxyNetworkACL: v })}
          rows={5}
          disabled={!en.dnsReverseProxyNetworkACL}
          help={
            <>
              Configure the ACL above to allow requests coming from your reverse proxy server for
              DNS-over-UDP-PROXY, DNS-over-TCP-PROXY, and DNS-over-HTTP protocols. Enter IP addresses
              or network addresses one below another to allow access. Add <code>!</code> character
              at the start to deny access, e.g. <code>!192.168.10.0/24</code> will deny entire
              subnet. The ACL is processed in the same order its listed. If no networks match, the
              default policy is to deny all.
            </>
          }
        />
        <TextRow
          label="Real IP Header"
          value={f.dnsOverHttpRealIpHeader}
          onChange={(v) => set({ dnsOverHttpRealIpHeader: v })}
          placeholder="X-Real-IP"
          maxLength={255}
          width="wide"
          disabled={!en.dnsOverHttpRealIpHeader}
          help={
            <>
              The HTTP header that must be used to read client's actual IP address when the request
              comes from a reverse proxy. The specified header will be read only when the request IP
              address is allowed by the <b>Reverse Proxy Network ACL</b>.
            </>
          }
        />
      </Block>

      <Block title="TLS Certificate">
        <TextRow
          label="TLS Certificate File Path"
          value={f.dnsTlsCertificatePath}
          onChange={(v) => set({ dnsTlsCertificatePath: v })}
          placeholder="DNS Service TLS Certificate File Path On Server"
          maxLength={255}
          width="wide"
          disabled={!en.dnsTlsCert}
          help="Specify a PKCS #12 certificate (.pfx or .p12) file path on the server. The path can be relative to the DNS Server's config folder. The certificate must contain private key."
        />
        <TextRow
          label="TLS Certificate Password"
          type="password"
          value={f.dnsTlsCertificatePassword}
          onChange={(v) => set({ dnsTlsCertificatePassword: v })}
          placeholder="DNS Service TLS Certificate Password"
          maxLength={255}
          width="wide"
          disabled={!en.dnsTlsCert}
          help="Enter the certificate (.pfx) password, if any."
        />
        <Avisos>
          <Note>
            These optional DNS Server protocol changes will be automatically applied and so you do
            not need to manually restart the main service. The TLS certificate too will be
            automatically reloaded when the certificate file's date modified property on disk
            changes. The DNS-over-TLS, DNS-over-QUIC, and DNS-over-HTTPS protocols will be enabled
            only when a TLS certificate is configured.
          </Note>
          <Note>
            These optional DNS Server protocols are used to host these as a service. You do not need
            to enable these optional protocols to use them with Forwarders or Conditional Forwarder
            Zones.
          </Note>
          <Note>
            For DNS-over-HTTP, use <code>http://localhost:8053/dns-query</code> with a TLS
            terminating reverse proxy like nginx. For DNS-over-TLS, use{' '}
            <code>tls-certificate-domain:853</code>, for DNS-over-QUIC, use{' '}
            <code>tls-certificate-domain:853</code>, and for DNS-over-HTTPS use{' '}
            <code>https://tls-certificate-domain/dns-query</code> to configure supported DNS clients.
          </Note>
          <Note>
            When using a reverse proxy with the DNS-over-HTTP service, you need to add{' '}
            <code>{f.dnsOverHttpRealIpHeader || 'X-Real-IP'}</code> header to the proxy request with
            the IP address of the client to allow the DNS Server to know the real IP address of the
            client originating the request. For example, if you are using nginx as the reverse
            proxy, you can add{' '}
            <code>proxy_set_header {f.dnsOverHttpRealIpHeader || 'X-Real-IP'} $remote_addr;</code>{' '}
            to make it work.
          </Note>
          <Note>
            DNS-over-QUIC protocol support is not available on all platforms. On Windows, it is
            available only on Windows 11 (build 22000 and later) and Windows Server 2022 (and
            later). On Linux, it requires <code>libmsquic</code> to be installed. It also requires
            IPv6 support on the system to work.
          </Note>
          <Note>
            The DNS-over-HTTP/3 protocol will always bind to <code>[::]</code> local address since
            this is how the <code>libmsquic</code> library is designed to work.
          </Note>
          <Note>
            Unix Domain Sockets (UDS) are supported only on Linux, Windows 10 (build 17063 and
            later), and Windows Server 2019 (update 1809 and later).
          </Note>
        </Avisos>
        <Plain>
          Use the following openssl command to convert your TLS certificate that is in PEM format to
          PKCS #12 certificate (.pfx) format:
        </Plain>
        <Pre>
          openssl pkcs12 -export -out "example.com.pfx" -inkey "privkey.pem" -in "cert.pem"
          -certfile "chain.pem"
        </Pre>
        <Help href="https://blog.technitium.com/2020/07/how-to-host-your-own-dns-over-https-and.html">
          Help: How To Host Your Own DNS-over-HTTPS, DNS-over-TLS, And DNS-over-QUIC Services
        </Help>
        <Help href="https://blog.technitium.com/2023/02/configuring-dns-over-quic-and-https3.html">
          Help: Configuring DNS-over-QUIC and HTTPS/3 For Technitium DNS Server
        </Help>
      </Block>
    </>
  )
}
