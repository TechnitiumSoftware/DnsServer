import { AreaRow, Notices, Block, Check, GroupRow, Help, Note, Plain, Pre, TextRow } from '../parts'
import type { PaneProps } from './tipos'

/*
Settings > Web Service (index.html:1416-1560).

Upstream draws it in a single `div.well`; here it is split into titled blocks
without moving a single field or changing their order.
*/
export function WebService({ f, set, en }: PaneProps) {
  return (
    <>
      <Block title="Listeners">
        <AreaRow
          label="Web Service Local Addresses"
          value={f.webServiceLocalAddresses}
          onChange={(v) => set({ webServiceLocalAddresses: v })}
          help="Local addresses are the network interface IP addresses you want the Web Service to listen for requests. ANY addresses (0.0.0.0 & [::]) cannot be used together with unicast IP addresses. The web server uses dual-mode sockets by default so the IPv6 ANY address ([::]) works for IPv4 too. The default values work for most scenarios so, do not change these defaults unless you have a requirement for the Web Service to listen on specific networks. Configured unicast IP addresses will be included as Subject Alternative Name (SAN) in the self signed TLS certificate."
        />
        <TextRow
          label="Web Service HTTP Port"
          type="number"
          value={f.webServiceHttpPort}
          onChange={(v) => set({ webServiceHttpPort: v })}
          placeholder="port"
          suffix="(default 5380)"
          help="Specify the TCP port number for this web console over HTTP protocol."
        />
      </Block>

      <Block title="Unix Domain Sockets">
        <GroupRow label="Unix Domain Sockets (UDS)">
          <Check
            toggle
            label="Enable HTTP Unix Domain Sockets (UDS)"
            checked={f.webServiceEnableHttpUnixSocket}
            onChange={(v) => set({ webServiceEnableHttpUnixSocket: v })}
            help="Enables Web Service HTTP over Unix Domain Sockets (UDS)."
          />
          <Check
            toggle
            label="Enable HTTPS Unix Domain Sockets (UDS)"
            checked={f.webServiceEnableTlsUnixSocket}
            onChange={(v) => set({ webServiceEnableTlsUnixSocket: v })}
            help="Enables Web Service HTTPS over Unix Domain Sockets (UDS)."
          />
        </GroupRow>
        <TextRow
          label="Web Service HTTP UDS File Path"
          value={f.webServiceHttpUnixSocket}
          onChange={(v) => set({ webServiceHttpUnixSocket: v })}
          placeholder="/path/to/http.sock"
          width="wide"
          disabled={!en.webServiceHttpUnixSocket}
          help="Specify the Unix Domain Sockets (UDS) file path for HTTP Web Service. Ensure that the DNS Server has read+write permissions to the parent directory to be able to create the UDS file."
        />
        <TextRow
          label="Web Service HTTPS UDS File Path"
          value={f.webServiceTlsUnixSocket}
          onChange={(v) => set({ webServiceTlsUnixSocket: v })}
          placeholder="/path/to/https.sock"
          width="wide"
          disabled={!en.webServiceTlsUnixSocket}
          help="Specify the Unix Domain Sockets (UDS) file path for HTTPS Web Service. Ensure that the DNS Server has read+write permissions to the parent directory to be able to create the UDS file."
        />
      </Block>

      <Block title="HTTPS Options">
        <GroupRow label="HTTPS Options">
          <Check
            toggle
            label="Enable HTTPS"
            checked={f.webServiceEnableTls}
            onChange={(v) => set({ webServiceEnableTls: v })}
          />
          <Check
            toggle
            label="Enable HTTP/3"
            checked={f.webServiceEnableHttp3}
            onChange={(v) => set({ webServiceEnableHttp3: v })}
            disabled={!en.webServiceEnableHttp3}
          />
          <Check
            toggle
            label="Enable HTTP to HTTPS Redirection"
            checked={f.webServiceHttpToTlsRedirect}
            onChange={(v) => set({ webServiceHttpToTlsRedirect: v })}
            disabled={!en.webServiceHttpToTlsRedirect}
          />
          <Check
            toggle
            label="Use A Self Signed TLS Certificate When TLS Certificate File Path Is Unspecified"
            checked={f.webServiceUseSelfSignedTlsCertificate}
            onChange={(v) => set({ webServiceUseSelfSignedTlsCertificate: v })}
            disabled={!en.webServiceTlsCert}
          />
        </GroupRow>
        <TextRow
          label="Web Service HTTPS Port"
          type="number"
          value={f.webServiceTlsPort}
          onChange={(v) => set({ webServiceTlsPort: v })}
          placeholder="port"
          suffix="(default 53443)"
          disabled={!en.webServiceTlsPort}
          help="Specify the TCP port number for this web console over TLS protocol."
        />
      </Block>

      <Block title="Reverse Proxy">
        <AreaRow
          label="Reverse Proxy Addresses"
          value={f.webServiceReverseProxyAddresses}
          onChange={(v) => set({ webServiceReverseProxyAddresses: v })}
          rows={5}
          help={
            <>
              Configure the ACL above to define allowed reverse proxy servers such that client IP
              address from requests coming from these servers is read using the <b>Real IP Header</b>{' '}
              configured below. Enter IP addresses or network addresses one below another to allow.
              Add <code>!</code> character at the start to deny, e.g.{' '}
              <code>!192.168.10.0/24</code> will deny entire subnet. The ACL is processed in the
              same order its listed. If no networks match, the default policy is to deny all.
            </>
          }
        />
        <TextRow
          label="Real IP Header"
          value={f.webServiceRealIpHeader}
          onChange={(v) => set({ webServiceRealIpHeader: v })}
          placeholder="X-Real-IP"
          maxLength={255}
          width="wide"
          help={
            <>
              The HTTP header that must be used to read client's current IP address when the request
              comes from a reverse proxy whose IP address is allowed in <b>Reverse Proxy Addresses</b>{' '}
              ACL above.
            </>
          }
        />
        <TextRow
          label="CSP Frame Ancestors Header"
          value={f.webServiceCspFrameAncestorsHeader}
          onChange={(v) => set({ webServiceCspFrameAncestorsHeader: v })}
          placeholder="'none'"
          maxLength={255}
          width="wide"
          help="The Content Security Policy (CSP) Frame Ancestors header value that must be used when serving the Web Console."
        />
      </Block>

      <Block title="TLS Certificate">
        <TextRow
          label="TLS Certificate File Path"
          value={f.webServiceTlsCertificatePath}
          onChange={(v) => set({ webServiceTlsCertificatePath: v })}
          placeholder="Web Service TLS Certificate File Path On Server"
          maxLength={255}
          width="wide"
          disabled={!en.webServiceTlsCert}
          help="Specify a PKCS #12 certificate (.pfx or .p12) file path on the server. The path can be relative to the DNS Server's config folder. The certificate must contain private key."
        />
        <TextRow
          label="TLS Certificate Password"
          type="password"
          value={f.webServiceTlsCertificatePassword}
          onChange={(v) => set({ webServiceTlsCertificatePassword: v })}
          placeholder="Web Service TLS Certificate Password"
          maxLength={255}
          width="wide"
          disabled={!en.webServiceTlsCert}
          help="Enter the certificate (.pfx) password, if any."
        />
        <Notices>
          <Note>
            The Web Service port changes will be automatically applied and so you do not need to
            manually restart the main service. The TLS certificate too will be automatically
            reloaded when the certificate file's date modified property on disk changes. This web
            page will be automatically redirected to the new web console URL after saving settings.
            The HTTPS protocol will be enabled only when a TLS certificate is configured.
          </Note>
          <Note>
            When using a reverse proxy with the Web Service, you need to add{' '}
            <code>{f.webServiceRealIpHeader || 'X-Real-IP'}</code> header to the proxy request with
            the IP address of the client to allow the Web Service to know the real IP address of the
            client originating the request. For example, if you are using nginx as the reverse
            proxy, you can add{' '}
            <code>proxy_set_header {f.webServiceRealIpHeader || 'X-Real-IP'} $remote_addr;</code> to
            make it work.
          </Note>
          <Note>
            The Web Service uses Kestrel web server which supports both HTTP/2 and HTTP/3 protocols
            when TLS certificate is configured. HTTP/3 protocol support is not available on all
            platforms. On Windows, it is available only on Windows 11 (build 22000 and later) and
            Windows Server 2022 (and later). On Linux, it requires <code>libmsquic</code> to be
            installed. It also requires IPv6 support on the system to work.
          </Note>
          <Note>
            The Web Service will always bind to <code>[::]</code> local address for HTTP/3 protocol
            since this is how the <code>libmsquic</code> library is designed to work.
          </Note>
          <Note>
            Unix Domain Sockets (UDS) are supported only on Linux, Windows 10 (build 17063 and
            later), and Windows Server 2019 (update 1809 and later).
          </Note>
        </Notices>
        <Plain>
          Use the following openssl command to convert your TLS certificate that is in PEM format to
          PKCS #12 certificate (.pfx) format:
        </Plain>
        <Pre>
          openssl pkcs12 -export -out "example.com.pfx" -inkey "privkey.pem" -in "cert.pem"
          -certfile "chain.pem"
        </Pre>
        <Help href="https://blog.technitium.com/2023/02/configuring-dns-over-quic-and-https3.html">
          Help: Configuring DNS-over-QUIC and HTTPS/3 For Technitium DNS Server
        </Help>
      </Block>
    </>
  )
}
