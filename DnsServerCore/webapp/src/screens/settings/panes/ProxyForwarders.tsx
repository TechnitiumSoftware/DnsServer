import {
  AreaRow,
  Notices,
  Block,
  Check,
  GroupRow,
  Help,
  Note,
  Radios,
  TextRow,
} from '../parts'
import type { PaneProps } from './tipos'

/*
Settings > Proxy & Forwarders (index.html:2192-2358). Three blocks.

Careful with the proxy: when reading it arrives as a nested object and when
saving it is sent flat, and with "No Proxy" upstream does NOT send the address,
port, username, password or bypass list (main.js:2122). Switching to "No Proxy"
and saving deletes that data on the server: it is upstream's behaviour and it is
replicated.
*/
export function ProxyForwarders({ f, set, en }: PaneProps) {
  return (
    <>
      <Block title="Network Proxy">
        <GroupRow label="Network Proxy">
          <Radios
            name="rdProxyType"
            value={f.proxyType}
            onChange={(v) => set({ proxyType: v })}
            options={[
              { value: 'None', label: 'No Proxy (default)' },
              { value: 'Http', label: 'HTTP Proxy' },
              { value: 'Socks5', label: 'SOCKS5 Proxy' },
            ]}
          />
        </GroupRow>
        <TextRow
          label="Proxy Server Address"
          value={f.proxyAddress}
          onChange={(v) => set({ proxyAddress: v })}
          placeholder="domain name or IP address"
          maxLength={255}
          width="wide"
          disabled={!en.proxy}
        />
        <TextRow
          label="Proxy Server Port"
          type="number"
          value={f.proxyPort}
          onChange={(v) => set({ proxyPort: v })}
          placeholder="port"
          disabled={!en.proxy}
        />
        <TextRow
          label="Username"
          value={f.proxyUsername}
          onChange={(v) => set({ proxyUsername: v })}
          placeholder="username"
          maxLength={255}
          width="wide"
          disabled={!en.proxy}
        />
        <TextRow
          label="Password"
          type="password"
          value={f.proxyPassword}
          onChange={(v) => set({ proxyPassword: v })}
          placeholder="password"
          maxLength={255}
          width="wide"
          disabled={!en.proxy}
        />
        <AreaRow
          label="Proxy Bypass List"
          value={f.proxyBypassList}
          onChange={(v) => set({ proxyBypassList: v })}
          rows={5}
          disabled={!en.proxy}
          help="Enter IP addresses, network addresses or domain names to never proxy."
        />
        <Notices>
          <Note>
            When proxy server is configured, DNS Server will use it for all outbound network
            requests.
          </Note>
        </Notices>
      </Block>

      <Block title="Forwarders">
        <AreaRow
          label="Forwarders"
          value={f.forwarders}
          onChange={(v) => set({ forwarders: v })}
          help="Enter forwarder DNS Server IP addresses or URLs one below another in above text field or use the Quick Select list to select desired forwarder."
        />
        <GroupRow
          label="Forwarder Protocol"
          help="Select a protocol that this DNS Server must use to query the forwarders specified above."
        >
          <Radios
            name="rdForwarderProtocol"
            value={f.forwarderProtocol}
            onChange={(v) => set({ forwarderProtocol: v })}
            options={[
              { value: 'Udp', label: 'DNS-over-UDP (default)' },
              { value: 'Tcp', label: 'DNS-over-TCP' },
              { value: 'Tls', label: 'DNS-over-TLS' },
              { value: 'Https', label: 'DNS-over-HTTPS' },
              { value: 'Quic', label: 'DNS-over-QUIC' },
            ]}
          />
        </GroupRow>
        <GroupRow label="Concurrent Forwarding">
          <Check
            toggle
            label="Enable Concurrent Forwarding"
            checked={f.concurrentForwarding}
            onChange={(v) => set({ concurrentForwarding: v })}
            help="Enable this option to allow querying two or more forwarders concurrently instead of sequentially querying them in their given order. The DNS Server will automatically select forwarders (based on their average latency) to query and use the fastest response it receives from any of them. If none of the selected forwarders respond in time, the DNS Server will similarly select forwarders from the remaining ones and queries them till all are tried before giving up."
          />
        </GroupRow>
        <TextRow
          label="Forwarder Concurrency"
          type="number"
          value={f.forwarderConcurrency}
          onChange={(v) => set({ forwarderConcurrency: v })}
          placeholder="count"
          suffix="(valid range 1-10; default 2)"
          disabled={!en.forwarderConcurrency}
          help="The number of concurrent requests that must be sent when Concurrent Forwarding is enabled for resolving a domain name."
        />
        <Notices>
          <Note>
            Forwarders are upstream DNS servers which this DNS Server must use to resolve domain
            names. If no forwarders are configured then the DNS Server will use preconfigured ROOT
            HINTS to perform recursive resolution to resolve domain names.
          </Note>
          <Note>
            The <code>https</code> URL scheme supports only DNS-over-HTTPS/2 and DNS-over-HTTPS/1.1
            protocols. For DNS-over-HTTPS/3, use <code>h3</code> URL scheme instead of{' '}
            <code>https</code> but note that there wont be any protocol fallback if the connection
            attempt fails.
          </Note>
          <Note>
            The DNS Server uses Epsilon-Greedy machine learning algorithm and will automatically
            learn which of the forwarders are answering faster without errors and will use those
            forwarders most of the time.
          </Note>
          <Note>
            To customize the Quick Select drop down list, read the instructions given in the{' '}
            <code>www/json/readme.txt</code> file found in the installation folder.
          </Note>
        </Notices>
        <Help href="https://blog.technitium.com/2018/06/configuring-dns-server-for-privacy.html">
          Help: Configuring DNS Server For Privacy &amp; Security
        </Help>
        <Help href="https://blog.technitium.com/2023/02/configuring-dns-over-quic-and-https3.html">
          Help: Configuring DNS-over-QUIC and HTTPS/3 For Technitium DNS Server
        </Help>
      </Block>

      <Block title="Forwarder Options">
        <TextRow
          label="Forwarder Retries"
          type="number"
          value={f.forwarderRetries}
          onChange={(v) => set({ forwarderRetries: v })}
          placeholder="retries"
          suffix="(valid range 1-10; default 3)"
          help="The total number of retries the forwarder or conditional forwarder resolver must do per upstream DNS Server."
        />
        <TextRow
          label="Forwarder Timeout"
          type="number"
          value={f.forwarderTimeout}
          onChange={(v) => set({ forwarderTimeout: v })}
          placeholder="timeout"
          suffix="milliseconds (valid range 1000-10000; default 2000)"
          help="The amount of time the forwarder or conditional forwarder resolver must wait between retries."
        />
      </Block>
    </>
  )
}
