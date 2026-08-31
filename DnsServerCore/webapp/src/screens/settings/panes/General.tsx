import {
  AreaRow,
  Notices,
  Block,
  Check,
  EditableList,
  GroupRow,
  Note,
  Radios,
  TextRow,
  Warning,
} from '../parts'
import type { PaneProps } from './types'

/*
Settings > General. Ten blocks, in the order of upstream's `div.well`
(index.html:979-1414). Every label, suffix, help text and warning is an upstream
literal.
*/
export function General({ f, set, en }: PaneProps) {
  return (
    <>
      <Block title="Local Parameters">
        <TextRow
          label="DNS Server Domain"
          value={f.dnsServerDomain}
          onChange={(v) => set({ dnsServerDomain: v })}
          placeholder="domain name"
          maxLength={255}
          width="wide"
          help="The primary fully qualified domain name used by this DNS Server to identify itself."
        />
        <AreaRow
          label="DNS Server Local End Points"
          value={f.dnsServerLocalEndPoints}
          onChange={(v) => set({ dnsServerLocalEndPoints: v })}
          help={
            <>
              Local End Points are the network interface IP addresses and ports you want the DNS
              Server to listen for requests. To explicitly bind the UDP sockets to interface device
              on Linux, specify the interface name as shown in these examples:{' '}
              <code>192.168.1.10%eth0:53</code> or <code>[2001:db8::1%eth1]:53</code>. For VRF, the
              interface name can be the VRF name.
            </>
          }
        />
        <AreaRow
          label="DNS Server IPv4 Source Addresses"
          value={f.dnsServerIPv4SourceAddresses}
          onChange={(v) => set({ dnsServerIPv4SourceAddresses: v })}
          help="The IPv4 source addresses that the DNS Server must use for making all outbound DNS requests when the server is connected to two or more networks. Network addresses are also accepted."
        />
        <AreaRow
          label="DNS Server IPv6 Source Addresses"
          value={f.dnsServerIPv6SourceAddresses}
          onChange={(v) => set({ dnsServerIPv6SourceAddresses: v })}
          help={
            <>
              The IPv6 source addresses that the DNS Server must use for making all outbound DNS
              requests when the server is connected to two or more networks. Network addresses are
              also accepted. Note that this option will be used only when <code>Prefer IPv6</code>{' '}
              option is enabled.
            </>
          }
        />
        <Notices>
          <Note>
            The DNS Server local end point changes will be automatically applied and so you do not
            need to manually restart the main service.
          </Note>
          <Note>
            The source adddresses configured above must be the IP addresses that are configured on
            the local system's network interface. When using source addresses option, its also
            necessary to ensure that the system has a default route or a specific route for the
            source address to be able to reach the destination network. When source addresses are
            not configured, the IP address of the interface with a default route will be used as the
            source address.
          </Note>
        </Notices>
      </Block>

      <Block title="Default Parameters">
        <TextRow
          label="Default Record TTL"
          value={f.defaultRecordTtl}
          onChange={(v) => set({ defaultRecordTtl: v })}
          placeholder="TTL"
          suffix="seconds (default 3600/1h)"
          help="The default TTL value to use if not specified when adding or updating records in a Zone."
        />
        <TextRow
          label="Default NS Record TTL"
          value={f.defaultNsRecordTtl}
          onChange={(v) => set({ defaultNsRecordTtl: v })}
          placeholder="TTL"
          suffix="seconds (default 14400/4h)"
          help="The default TTL value to use if not specified when adding or updating NS records in a Primary Zone."
        />
        <TextRow
          label="Default SOA Record TTL"
          value={f.defaultSoaRecordTtl}
          onChange={(v) => set({ defaultSoaRecordTtl: v })}
          placeholder="TTL"
          suffix="seconds (default 900/15m)"
          help="The default TTL value to use if not specified when adding or updating SOA records in a Primary Zone."
        />
        <TextRow
          label="Default Responsible Person"
          value={f.defaultResponsiblePerson}
          onChange={(v) => set({ defaultResponsiblePerson: v })}
          placeholder="email address"
          maxLength={255}
          width="wide"
          help="The default SOA Responsible Person email address to use when adding a Primary Zone."
        />
        <GroupRow label="Zone Defaults">
          <Check
            toggle
            label="Use SOA Serial Date Scheme"
            checked={f.useSoaSerialDateScheme}
            onChange={(v) => set({ useSoaSerialDateScheme: v })}
            help="The default SOA Serial option to use if not specified when adding a Primary Zone."
          />
        </GroupRow>
        <TextRow
          label="Minimum SOA Refresh"
          value={f.minSoaRefresh}
          onChange={(v) => set({ minSoaRefresh: v })}
          placeholder="TTL"
          suffix="seconds (default 300/5m)"
          help="The minimum Refresh interval to be used by Secondary, Stub, Secondary Forwarder, and Secondary Catalog zones. This minimum value will be used if a zone's SOA Refresh value is less than it."
        />
        <TextRow
          label="Minimum SOA Retry"
          value={f.minSoaRetry}
          onChange={(v) => set({ minSoaRetry: v })}
          placeholder="TTL"
          suffix="seconds (default 300/5m)"
          help="The minimum Retry interval to be used by Secondary, Stub, Secondary Forwarder, and Secondary Catalog zones zones. This minimum value will be used if a zone's SOA Retry value is less than it."
        />
        <AreaRow
          label="Zone Transfer Allowed Networks"
          value={f.zoneTransferAllowedNetworks}
          onChange={(v) => set({ zoneTransferAllowedNetworks: v })}
          help="Enter IP addresses or network addresses one below another that are allowed to perform zone transfer for all zones without any TSIG authentication."
        />
        <AreaRow
          label="Notify Allowed Networks"
          value={f.notifyAllowedNetworks}
          onChange={(v) => set({ notifyAllowedNetworks: v })}
          help="Enter IP addresses or network addresses one below another that are allowed to Notify all Secondary Zones."
        />
      </Block>

      <Block title="Software Update">
        <GroupRow label="Software Update">
          <Check
            toggle
            label="Enable Check For Update"
            checked={f.dnsServerEnableCheckForUpdate}
            onChange={(v) => set({ dnsServerEnableCheckForUpdate: v })}
            help="Enables the DNS Server to check if an update is available when the Check For Update API is called which usually occurs after a user logs into the Web Console."
          />
          <Check
            toggle
            label="Enable Automatic Update"
            checked={f.dnsAppsEnableAutomaticUpdate}
            onChange={(v) => set({ dnsAppsEnableAutomaticUpdate: v })}
            help="The DNS Server will check for DNS Apps update once every day and will automatically download and install the updates."
          />
        </GroupRow>
      </Block>

      <Block title="IPv6">
        <GroupRow label="IPv6 Support">
          <Radios
            name="rdIPv6Mode"
            value={f.ipv6Mode}
            onChange={(v) => set({ ipv6Mode: v })}
            options={[
              {
                value: 'Disabled',
                label: 'Disable IPv6',
                help: 'Disables IPv6 support such that the DNS Server uses only IPv4 for all outbound DNS and HTTP(s) requests.',
              },
              {
                value: 'Enabled',
                label: 'Enable IPv6',
                help: 'Enables IPv6 support such that the DNS Server uses both IPv6 (whenever possible) and IPv4 with equal weightage for all outbound DNS and HTTP(s) requests.',
              },
              {
                value: 'Preferred',
                label: 'Prefer IPv6',
                help: 'Enables IPv6 support such that the DNS Server prefers using IPv6 (whenever possible) for all outbound DNS and HTTP(s) requests and will use IPv4 only after exhausting all IPv6 attempts.',
              },
            ]}
          />
        </GroupRow>
        <Notices>
          <Warning>
            Enable IPv6 support only if this DNS Server has native IPv6 Internet access otherwise it
            will affect performance. There are many name servers on the Internet that do not respond
            over IPv6 and thus using Prefer IPv6 option when you are running DNS Server in recursive
            resolver mode (i.e. without any forwarders) may cause frequent operational issues with
            resolution that may result increase in Server Failure responses.
          </Warning>
        </Notices>
      </Block>

      <Block title="UDP Socket Pool">
        <GroupRow label="UDP Socket Pool">
          <Check
            toggle
            label="Enable UDP Socket Pool"
            checked={f.enableUdpSocketPool}
            onChange={(v) => set({ enableUdpSocketPool: v })}
            help="The DNS Server will use UDP socket pool for all outbound DNS-over-UDP requests when enabled."
          />
        </GroupRow>
        <AreaRow
          label="UDP Socket Pool Excluded Ports"
          value={f.socketPoolExcludedPorts}
          onChange={(v) => set({ socketPoolExcludedPorts: v })}
          rows={5}
          disabled={!en.socketPoolExcludedPorts}
          help="Enter port numbers one below other to be excluded from being used by the UDP socket pool."
        />
        <Notices>
          <Note>
            Enabling UDP socket pool provides port randomization for all outbound DNS-over-UDP
            requests to mitigate spoofing attacks. It is recommended to enable UDP socket pool on
            Windows platform. On Linux, ports are fairly random and thus socket pool may be enabled
            if more randomization is desired. The DNS Server can detect DNS spoofing attack attempts
            based on ID mismatch and switch to TCP protocol automatically.
          </Note>
        </Notices>
      </Block>

      <Block title="EDNS">
        <TextRow
          label="EDNS UDP Payload Size"
          type="number"
          value={f.udpPayloadSize}
          onChange={(v) => set({ udpPayloadSize: v })}
          placeholder="size"
          suffix="bytes (valid range 512-4096; default 1232)"
          help="The maximum UDP payload size that can be used to avoid IP fragmentation."
        />
      </Block>

      <Block title="DNSSEC">
        <GroupRow label="DNSSEC">
          <Check
            toggle
            label="Enable DNSSEC Validation"
            checked={f.dnssecValidation}
            onChange={(v) => set({ dnssecValidation: v })}
            help="The DNS Server will validate all responses from name servers or forwarders when this option is enabled."
          />
        </GroupRow>
        <Notices>
          <Warning>
            Devices that do not have a real-time clock and rely on NTP when booting (e.g. Raspberry
            Pi), enabling DNSSEC validation will cause failure to resolve the NTP server domain name
            thus causing the DNS Server to fail to validate all other domain names too due to
            invalid system date/time. To fix this issue, just create a Conditional Forwarder zone
            for the NTP server domain name (e.g. ntp.org) with forwarder set to{' '}
            <code>this-server</code> and Enable DNSSEC Validation option unchecked. This conditional
            forwarder zone will disable DNSSEC validation for the NTP server domain name and allow
            the device to update its system data/time on boot.
          </Warning>
          <Warning>
            When forwarders are configured, DNSSEC validation will work only if the forwarders are
            security aware i.e. can respond to DNSSEC requests correctly.
          </Warning>
          <Note>
            Enabling DNSSEC may increase delays in resolving domain names when the cache is
            initially empty. As the cache fills up, the performance will be normal as expected.
          </Note>
        </Notices>
      </Block>

      <Block title="EDNS Client Subnet">
        <GroupRow label="EDNS Client Subnet (ECS)">
          <Check
            toggle
            label="Enable EDNS Client Subnet"
            checked={f.eDnsClientSubnet}
            onChange={(v) => set({ eDnsClientSubnet: v })}
            help="The DNS Server will use the public IP address of the request with a prefix length, or the existing Client Subnet option from the request."
          />
        </GroupRow>
        <TextRow
          label="ECS IPv4 Prefix Length"
          type="number"
          value={f.eDnsClientSubnetIPv4PrefixLength}
          onChange={(v) => set({ eDnsClientSubnetIPv4PrefixLength: v })}
          placeholder="prefix"
          suffix="(valid range 0-32; default 24)"
          disabled={!en.ecs}
          help="The IPv4 prefix length to define the client subnet."
        />
        <TextRow
          label="ECS IPv6 Prefix Length"
          type="number"
          value={f.eDnsClientSubnetIPv6PrefixLength}
          onChange={(v) => set({ eDnsClientSubnetIPv6PrefixLength: v })}
          placeholder="prefix"
          suffix="(valid range 0-64; default 56)"
          disabled={!en.ecs}
          help="The IPv6 prefix length to define the client subnet."
        />
        <TextRow
          label="ECS IPv4 Override"
          value={f.eDnsClientSubnetIpv4Override}
          onChange={(v) => set({ eDnsClientSubnetIpv4Override: v })}
          placeholder="network address"
          width="wide"
          disabled={!en.ecs}
          help="The IPv4 network address that must be used as ECS for all outbound requests overriding client's actual subnet."
        />
        <TextRow
          label="ECS IPv6 Override"
          value={f.eDnsClientSubnetIpv6Override}
          onChange={(v) => set({ eDnsClientSubnetIpv6Override: v })}
          placeholder="network address"
          width="wide"
          disabled={!en.ecs}
          help="The IPv6 network address that must be used as ECS for all outbound requests overriding client's actual subnet."
        />
        <Notices>
          <Warning>
            EDNS Client Subnet (ECS) option when enabled will compromises user's privacy since the
            DNS Server will send the user's public IP network subnet to name servers or forwarders
            when resolving requests. When not using encrypted DNS protocols, this information can
            also be read passively by anyone on the network.
          </Warning>
          <Note>
            EDNS Client Subnet (ECS) option allows passing the user's client subnet information to
            name servers or forwarders so that the response may contain IP addresses of servers
            closer to the user's geographic region. EDNS Client Subnet (ECS) option thus is only
            useful when the DNS Server is hosted in a geographically different region compared to
            the users that are configured to use it.
          </Note>
          <Note>
            Enabling EDNS Client Subnet (ECS) option will significantly increase the DNS Server's
            memory usage since the server will have to cache data for each client subnet separately.
            It will also increase cache misses since DNS Server will have to resolve requests and
            cache them for each client subnet separately.
          </Note>
        </Notices>
      </Block>

      <Block title="Rate Limiting">
        <EditableList
          label="Queries Per Minute (QPM) Limits (IPv4)"
          columns={[
            { key: 'prefix', label: 'IPv4 Prefix', type: 'number' },
            { key: 'udpLimit', label: 'UDP Limit', type: 'number' },
            { key: 'tcpLimit', label: 'TCP Limit', type: 'number' },
          ]}
          rows={f.qpmPrefixLimitsIPv4}
          onChange={(rows) => set({ qpmPrefixLimitsIPv4: rows })}
          blank={() => ({ prefix: '', udpLimit: '', tcpLimit: '' })}
          help={
            <>
              The maximum queries an IPv4 client subnet can make to DNS-over-UDP and DNS-over-TCP
              protocol services per minute on average based on the sample size. Set limit value to{' '}
              <code>0</code> to allow unlimited queries for a specific protocol in an entry or
              delete the entry altogether to remove rate limiting for the prefix.
            </>
          }
        />
        <EditableList
          label="Queries Per Minute (QPM) Limits (IPv6)"
          columns={[
            { key: 'prefix', label: 'IPv6 Prefix', type: 'number' },
            { key: 'udpLimit', label: 'UDP Limit', type: 'number' },
            { key: 'tcpLimit', label: 'TCP Limit', type: 'number' },
          ]}
          rows={f.qpmPrefixLimitsIPv6}
          onChange={(rows) => set({ qpmPrefixLimitsIPv6: rows })}
          blank={() => ({ prefix: '', udpLimit: '', tcpLimit: '' })}
          help={
            <>
              The maximum queries an IPv6 client subnet can make to DNS-over-UDP and DNS-over-TCP
              protocol services per minute on average based on the sample size. Set limit value to{' '}
              <code>0</code> to allow unlimited queries for a specific protocol in an entry or
              delete the entry altogether to remove rate limiting for the prefix.
            </>
          }
        />
        <TextRow
          label="QPM Sample Size"
          type="number"
          value={f.qpmLimitSampleMinutes}
          onChange={(v) => set({ qpmLimitSampleMinutes: v })}
          placeholder="sample"
          suffix="minutes (valid range 1-60; default 5)"
          help="The sample size in minutes to sample latest data from Last Hour stats for limiting queries per client."
        />
        <TextRow
          label="QPM Limit UDP Truncation"
          type="number"
          value={f.qpmLimitUdpTruncationPercentage}
          onChange={(v) => set({ qpmLimitUdpTruncationPercentage: v })}
          placeholder="%"
          suffix="% (valid range 0-100; default 50)"
          help="The percentage of requests that are responded with a truncation (TC) response when QPM limit exceeds for DNS-over-UDP protocol service while the rest of the requests are dropped. A TC response will cause a real client to retry to DNS-over-TCP protocol service."
        />
        <AreaRow
          label="QPM Limit Bypass List"
          value={f.qpmLimitBypassList}
          onChange={(v) => set({ qpmLimitBypassList: v })}
          rows={5}
          help="Enter IP addresses or network addresses one below another that are allowed to bypass the QPM limit."
        />
        <Notices>
          <Note>
            Queries Per Minute (QPM) feature will limit requests from a client subnet based on its
            IP address and the specified subnet prefix lengths except for loopback IP addresses. The
            QPM limit configured will be compared with the average count from the sample size which
            means a client may exceed the QPM limit for a given minute but won't exceed for the
            given sample size in minutes. Rate limited clients will be listed in orange color on the
            dashboard top clients table.
          </Note>
          <Note>
            The configured TCP limits apply to the DNS-over-TCP protocol service as well as to the
            DNS-over-TLS, DNS-over-HTTPS and DNS-over-QUIC optional protocol services.
          </Note>
        </Notices>
      </Block>

      <Block title="Advanced Options">
        <TextRow
          label="Client Timeout"
          type="number"
          value={f.clientTimeout}
          onChange={(v) => set({ clientTimeout: v })}
          placeholder="timeout"
          suffix="milliseconds (valid range 1000-10000; default 2000)"
          help={
            <>
              The amount of time the DNS Server must wait before responding with a{' '}
              <code>ServerFailure</code> response to a client request when no answer is available.
            </>
          }
        />
        <TextRow
          label="TCP Send Timeout"
          type="number"
          value={f.tcpSendTimeout}
          onChange={(v) => set({ tcpSendTimeout: v })}
          placeholder="timeout"
          suffix="milliseconds (valid range 1000-90000; default 10000)"
          help="The maximum amount of time the DNS Server will wait for the response to be sent. This option will apply for DNS requests being received by the DNS Server over TCP, TLS, TcpProxy, or HTTPS transports."
        />
        <TextRow
          label="TCP Receive Timeout"
          type="number"
          value={f.tcpReceiveTimeout}
          onChange={(v) => set({ tcpReceiveTimeout: v })}
          placeholder="timeout"
          suffix="milliseconds (valid range 1000-90000; default 10000)"
          help="The maximum amount of time the DNS Server will wait for receiving data. This option will apply for DNS requests being received by the DNS Server over TCP, TLS, TcpProxy, or HTTPS transports."
        />
        <TextRow
          label="QUIC Idle Timeout"
          type="number"
          value={f.quicIdleTimeout}
          onChange={(v) => set({ quicIdleTimeout: v })}
          placeholder="timeout"
          suffix="milliseconds (valid range 1000-90000; default 60000)"
          help="The time interval after which an idle QUIC connection will be closed. This option applies only to QUIC transport protocol."
        />
        <TextRow
          label="QUIC Max Inbound Streams"
          type="number"
          value={f.quicMaxInboundStreams}
          onChange={(v) => set({ quicMaxInboundStreams: v })}
          placeholder="100"
          suffix="(valid range 1-1000; default 100)"
          help="The max number of inbound bidirectional streams that can be accepted per QUIC connection. This option applies only to QUIC transport protocol."
        />
        <TextRow
          label="Listen Backlog"
          type="number"
          value={f.listenBacklog}
          onChange={(v) => set({ listenBacklog: v })}
          placeholder="100"
          suffix="(default 100)"
          help="The maximum number of pending inbound connections. This option applies to TCP, TLS, TcpProxy, and QUIC transport protocols."
        />
        <TextRow
          label="UDP Send Buffer Size"
          type="number"
          value={f.udpSendBufferSizeKB}
          onChange={(v) => set({ udpSendBufferSizeKB: v })}
          placeholder="2048"
          suffix="KB (valid range 8-65536; default 2048)"
          help="The UDP listener socket send buffer size. This option applies to UDP and UdpProxy transport protocols."
        />
        <TextRow
          label="UDP Receive Buffer Size"
          type="number"
          value={f.udpReceiveBufferSizeKB}
          onChange={(v) => set({ udpReceiveBufferSizeKB: v })}
          placeholder="2048"
          suffix="KB (valid range 8-65536; default 2048)"
          help="The UDP listener socket receive buffer size. This option applies to UDP and UdpProxy transport protocols."
        />
        <TextRow
          label="Max Concurrent Resolutions"
          type="number"
          value={f.maxConcurrentResolutionsPerCore}
          onChange={(v) => set({ maxConcurrentResolutionsPerCore: v })}
          placeholder="100"
          suffix="per CPU core (default 100)"
          help="The maximum number of concurrent async outbound resolutions that should be done per CPU core."
        />
      </Block>
    </>
  )
}
