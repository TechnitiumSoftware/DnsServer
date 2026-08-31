import { useState } from 'react'
import { Button } from '../../ui/Button'
import { Input, Textarea } from '../../ui/Field'
import {
  buildBody,
  cellId,
  type ScopeError,
  type ScopeForm as Form,
} from './model'
import {
  AreaRow,
  Notices,
  Block,
  Check,
  EditableList,
  GroupRow,
  Note,
  Row,
  TextRow,
  Warning,
} from './parts'
import { SectionHeader } from '../../ui/SectionHeader'
import styles from './Dhcp.module.css'

/*
A scope's form (index.html:2560-2930). In upstream it is NOT a modal: it replaces
the table inside the Scopes sub-tab itself, with the title "Add Scope" or "Edit
Scope" as the case may be. It is kept that way.

The labels, the help texts, the placeholders and the order of the thirteen groups
are upstream literals. The "Warning!" and "Note!" alerts are bold paragraphs
there; here they are coloured blocks, which is the only difference.

Two dependencies between fields that upstream implements with `onclick` and that
here are state, to the same effect:

  · "Enable DNS Updates" unchecked disables "Enable DNS Overwrite For Dynamic
    Lease" (dhcp.js:21-25).
  · "Use This DNS Server" checked disables the DNS servers area
    (index.html:2713).
*/

export function ScopeForm({
  title,
  inicial,
  busy,
  onSave,
  onCancelar,
  onNotice,
}: {
  title: 'Add Scope' | 'Edit Scope'
  inicial: Form
  busy: boolean
  onSave: (body: Record<string, string>) => void
  onCancelar: () => void
  onNotice: (e: ScopeError) => void
}) {
  const [f, setF] = useState<Form>(inicial)

  function set(parcial: Partial<Form>) {
    setF((prev) => ({ ...prev, ...parcial }))
  }

  function save() {
    const result = buildBody(f)
    if ('error' in result) {
      onNotice(result.error)
      document.getElementById(result.error.focus)?.focus()
      return
    }
    onSave(result.body)
  }

  return (
    <div>
      <SectionHeader section="DHCP" title={title} />

      <Block title="Scope">
        <TextRow
          label="Name"
          value={f.name}
          onChange={(v) => set({ name: v })}
          placeholder="Scope Name"
          width="wide"
        />
        <TextRow
          label="Starting Address"
          value={f.startingAddress}
          onChange={(v) => set({ startingAddress: v })}
          placeholder="Starting Address"
          width="wide"
        />
        <TextRow
          label="Ending Address"
          value={f.endingAddress}
          onChange={(v) => set({ endingAddress: v })}
          placeholder="Ending Address"
          width="wide"
        />
        <TextRow
          label="Subnet Mask"
          value={f.subnetMask}
          onChange={(v) => set({ subnetMask: v })}
          placeholder="Subnet Mask"
          width="wide"
        />

        <GroupRow
          label="Lease Time"
          help="The duration for which the clients should be leased the IP address."
        >
          <div className={styles.ctlLine}>
            <label className={styles.suffix} htmlFor="dhcp-leaseTimeDays">
              Days
            </label>
            <Input
              id="dhcp-leaseTimeDays"
              type="number"
              style={{ width: 80 }}
              placeholder="Days"
              value={f.leaseTimeDays}
              onChange={(e) => set({ leaseTimeDays: e.target.value })}
            />
            <label className={styles.suffix} htmlFor="dhcp-leaseTimeHours">
              Hours
            </label>
            <Input
              id="dhcp-leaseTimeHours"
              type="number"
              style={{ width: 80 }}
              placeholder="Hrs"
              value={f.leaseTimeHours}
              onChange={(e) => set({ leaseTimeHours: e.target.value })}
            />
            <label className={styles.suffix} htmlFor="dhcp-leaseTimeMinutes">
              Minutes
            </label>
            <Input
              id="dhcp-leaseTimeMinutes"
              type="number"
              style={{ width: 80 }}
              placeholder="Mins"
              value={f.leaseTimeMinutes}
              onChange={(e) => set({ leaseTimeMinutes: e.target.value })}
            />
          </div>
        </GroupRow>

        <TextRow
          label="Offer Delay Time"
          type="number"
          width={80}
          suffix="milliseconds"
          placeholder="Delay"
          value={f.offerDelayTime}
          onChange={(v) => set({ offerDelayTime: v })}
          help="The time duration that the DHCP server delays sending an DHCPOFFER message."
        />
      </Block>

      <Block title="Ping Check">
        <GroupRow label="Ping Check">
          <Check
            toggle
            label="Enable Ping Check"
            checked={f.pingCheckEnabled}
            onChange={(v) => set({ pingCheckEnabled: v })}
            help="Enable this option to allow DHCP server to find out if an IP address is already in use to prevent IP address conflict when some of the devices on the network have manually configured IP addresses."
          />
        </GroupRow>
        <TextRow
          label="Ping Check Timeout"
          type="number"
          suffix="milliseconds (default 1000)"
          placeholder="timeout"
          value={f.pingCheckTimeout}
          onChange={(v) => set({ pingCheckTimeout: v })}
          help="The timeout interval to wait for an ping reply."
        />
        <TextRow
          label="Ping Check Retries"
          type="number"
          suffix="(default 2)"
          placeholder="retry"
          value={f.pingCheckRetries}
          onChange={(v) => set({ pingCheckRetries: v })}
          help="The maximum number of ping requests to try."
        />
        <Notices>
          <Warning>
            Ping check would work as expected only when you make sure that all the client devices with
            manually configured IP addresses on the network respond to a ping request. Devices running
            Microsoft Windows by default drop ping requests at host firewall and will cause this ping
            check to fail to detect in use IP addresses. It is recommended to not rely on this option
            and instead make sure that you exclude a range of addresses using Exclusions and manually
            assign IP addresses to your devices only in the excluded range.
          </Warning>
        </Notices>
      </Block>

      <Block title="DNS">
        <TextRow
          label="Domain Name"
          width="wide"
          placeholder="Domain Name"
          value={f.domainName}
          onChange={(v) => set({ domainName: v })}
          help="The domain name for this network to allow assigning a fully qualified domain name to clients. Use a domain name that you own or that is not in common use like 'home' or 'lan' so that you don't block out an existing domain name. (Option 15)"
        />
        <AreaRow
          label="Domain Search List"
          value={f.domainSearchList}
          onChange={(v) => set({ domainSearchList: v })}
          help="The list of domain names that the clients can use as a suffix when searching a domain name. (Option 119)"
        />
        <GroupRow label="DNS Updates">
          <Check
            toggle
            label="Enable DNS Updates"
            checked={f.dnsUpdates}
            onChange={(v) => set({ dnsUpdates: v })}
            help="Enable this option to allow the DHCP server to automatically update forward and reverse DNS entries for clients."
          />
          <Check
            toggle
            label="Enable DNS Overwrite For Dynamic Lease"
            checked={f.dnsOverwriteForDynamicLease}
            disabled={!f.dnsUpdates}
            onChange={(v) => set({ dnsOverwriteForDynamicLease: v })}
            help="Enable this option to allow the DHCP server to overwrite existing DNS A record matching the client domain name for dynamic leases."
          />
        </GroupRow>
        <TextRow
          label="DNS TTL"
          suffix="seconds (default 900/15m)"
          placeholder="DNS TTL"
          value={f.dnsTtl}
          onChange={(v) => set({ dnsTtl: v })}
          help="The TTL value of the DNS records updated for the above provided domain name."
        />
      </Block>

      <Block title="Network Options">
        <TextRow
          label="Router Address"
          width="wide"
          placeholder="Router Address"
          value={f.routerAddress}
          onChange={(v) => set({ routerAddress: v })}
          help="The default gateway IP address to be used by the clients. (Option 3)"
        />
        {/* index.html:2708-2722 — a single "DNS Servers" label for the whole
            row: it governs the text area, and the checkbox carries its own. */}
        <Row label="DNS Servers" help="The DNS Server IP addresses to be used by the clients. (Option 6)">
          {(id) => (
            <>
              <Check
                toggle
                label="Use This DNS Server"
                checked={f.useThisDnsServer}
                onChange={(v) => set({ useThisDnsServer: v })}
                help="Enable this option to automatically use this DNS Server."
              />
              <Textarea
                mono
                id={id}
                className={styles.area}
                rows={2}
                spellCheck={false}
                disabled={f.useThisDnsServer}
                value={f.dnsServers}
                onChange={(e) => set({ dnsServers: e.target.value })}
              />
            </>
          )}
        </Row>
        <AreaRow
          label="WINS Servers"
          value={f.winsServers}
          onChange={(v) => set({ winsServers: v })}
          help="The NBNS/WINS server IP addresses to be used by the clients. (Option 44)"
        />
        <AreaRow
          label="NTP Servers"
          value={f.ntpServers}
          onChange={(v) => set({ ntpServers: v })}
          help="The Network Time Protocol (NTP) server IP addresses to be used by the clients. (Option 42)"
        />
        <AreaRow
          label="NTP Server Domain Names"
          value={f.ntpServerDomainNames}
          onChange={(v) => set({ ntpServerDomainNames: v })}
          help="Enter NTP server domain names (e.g. pool.ntp.org) above that the DHCP server should automatically resolve and pass the resolved IP addresses to clients as NTP server option. (Option 42)"
        />
      </Block>

      <Block title="Static Routes">
        <EditableList
          label="Static Routes"
          cellId={(row, column) => cellId('staticRoutes', row, column)}
          columns={[
            { key: 'destination', label: 'Destination' },
            { key: 'subnetMask', label: 'Subnet Mask' },
            { key: 'router', label: 'Router' },
          ]}
          rows={f.staticRoutes}
          onChange={(rows) => set({ staticRoutes: rows })}
          blank={() => ({ destination: '', subnetMask: '', router: '' })}
          help="The static routes to be used by the clients for accessing specified destination networks. (Option 121)"
        />
      </Block>

      <Block title="Bootstrap">
        <TextRow
          label="Bootstrap Server Address"
          width="wide"
          placeholder="Bootstrap Server Address"
          value={f.serverAddress}
          onChange={(v) => set({ serverAddress: v })}
          help="The IP address of next server (TFTP) to use in bootstrap by the clients. If not specified, the DHCP server's IP address is used. (siaddr)"
        />
        <TextRow
          label="Bootstrap Server Host Name"
          width="wide"
          placeholder="Bootstrap Server Host Name"
          value={f.serverHostName}
          onChange={(v) => set({ serverHostName: v })}
          help="The optional bootstrap server host name to be used by the clients to identify the TFTP server. (sname/Option 66)"
        />
        <TextRow
          label="Boot File Name"
          width="wide"
          placeholder="Boot File Name"
          value={f.bootFileName}
          onChange={(v) => set({ bootFileName: v })}
          help="The boot file name stored on the bootstrap TFTP server to be used by the clients. (file/Option 67)"
        />
      </Block>

      <Block title="Vendor Specific Information">
        <EditableList
          label="Vendor Specific Information"
          cellId={(row, column) => cellId('vendorInfo', row, column)}
          columns={[
            { key: 'identifier', label: 'Vendor Class Identifier' },
            { key: 'information', label: 'Vendor Specific Information' },
          ]}
          rows={f.vendorInfo}
          onChange={(rows) => set({ vendorInfo: rows })}
          blank={() => ({ identifier: '', information: '' })}
          help={
            <>
              The Vendor Specific Information (option 43) to be sent to the clients that match the
              Vendor Class Identifier (option 60) in the request. The Vendor Class Identifier can be
              empty string to match any identifier, or matched exactly, or match a substring, for
              example <code>substring(vendor-class-identifier,0,9)=="PXEClient"</code>. The Vendor
              Specific Information must be either a colon (:) separated hex string or a normal hex
              string, for example{' '}
              <code>
                06:01:03:0A:04:00:50:58:45:09:14:00:00:11:52:61:73:70:62:65:72:72:79:20:50:69:20:42:6F:6F:74:FF
              </code>{' '}
              OR <code>0601030A0400505845091400001152617370626572727920506920426F6F74FF</code>.
            </>
          }
        />
      </Block>

      <Block title="CAPWAP Access Controller Addresses">
        <AreaRow
          label="CAPWAP Access Controller Addresses"
          value={f.capwapAcIpAddresses}
          onChange={(v) => set({ capwapAcIpAddresses: v })}
          help="The Control And Provisioning of Wireless Access Points (CAPWAP) Access Controller IP addresses to be used by Wireless Termination Points to discover the Access Controllers to which it is to connect. (Option 138)"
        />
      </Block>

      <Block title="TFTP Server Addresses">
        <AreaRow
          label="TFTP Server Addresses"
          value={f.tftpServerAddresses}
          onChange={(v) => set({ tftpServerAddresses: v })}
          help="The TFTP Server Address or the VoIP Configuration Server Address. (Option 150)"
        />
      </Block>

      <Block title="Generic DHCP Options">
        <EditableList
          label="Generic DHCP Options"
          cellId={(row, column) => cellId('genericOptions', row, column)}
          columns={[
            { key: 'code', label: 'Code', type: 'number', min: 0, max: 255 },
            { key: 'value', label: 'Hex Value' },
          ]}
          rows={f.genericOptions}
          onChange={(rows) => set({ genericOptions: rows })}
          blank={() => ({ code: '', value: '' })}
          help={
            <>
              This feature allows you to define DHCP options that are not yet directly supported. To
              add an option, use the DHCP option code defined for it and enter the value in either a
              colon (:) separated hex string or a normal hex string format, for example{' '}
              <code>C0:A8:01:01</code> OR <code>C0A80101</code>.
            </>
          }
        />
      </Block>

      <Block title="Exclusions">
        <EditableList
          label="Exclusions"
          cellId={(row, column) => cellId('exclusions', row, column)}
          columns={[
            { key: 'startingAddress', label: 'Starting Address' },
            { key: 'endingAddress', label: 'Ending Address' },
          ]}
          rows={f.exclusions}
          onChange={(rows) => set({ exclusions: rows })}
          blank={() => ({ startingAddress: '', endingAddress: '' })}
          help="The IP address range that must be excluded or not assigned dynamically to any client by the DHCP server."
        />
        <Notices>
          <Note>
            Make sure to exclude address ranges if you plan to manually assign IP addresses to some of
            the devices or to assign reserved leases so that these IP addresses are not dynamically
            allocated in the first place.
          </Note>
        </Notices>
      </Block>

      <Block title="Advanced Options">
        <GroupRow label="Advanced Options">
          <Check
            toggle
            label="Allow Only Reserved Lease Allocations"
            checked={f.allowOnlyReservedLeases}
            onChange={(v) => set({ allowOnlyReservedLeases: v })}
            help="Enable this option to stop dynamic IP address allocation and allocate only reserved IP addresses."
          />
          <Check
            toggle
            label="Block Locally Administered MAC Addresses"
            checked={f.blockLocallyAdministeredMacAddresses}
            onChange={(v) => set({ blockLocallyAdministeredMacAddresses: v })}
            help={
              <>
                Enable this option to stop dynamic IP address allocation for clients with locally
                administered MAC addresses. MAC address with 0x02 bit set in the first octet
                indicate a{' '}
                <a
                  href="https://en.wikipedia.org/wiki/MAC_address"
                  target="_blank"
                  rel="noreferrer"
                >
                  locally administered
                </a>{' '}
                MAC address which usually means that the device is not using its original MAC
                address.
              </>
            }
          />
          <Check
            toggle
            label="Ignore Client Identifier (Option 61)"
            checked={f.ignoreClientIdentifierOption}
            onChange={(v) => set({ ignoreClientIdentifierOption: v })}
            help="This option when enabled will always use the client's MAC address as the identifier to allocate lease instead of the Client Identifier (Option 61) provided by the client in the request. Some Linux distros use a custom Client Identifier instead of the device's MAC Address which can cause issues when the Virtual Machine (VM) in which the OS is installed is cloned causing both the original and cloned clients to get same IP allocated. There can be issues too when the same client changes its Client Identifier and starts getting a different IP address lease. Enabling the Ignore Client Identifier option will fix such issues. Changing this option may cause the existing clients to get a different IP lease on renewal."
          />
        </GroupRow>
      </Block>

      <Block title="Reserved Leases">
        <EditableList
          label="Reserved Leases"
          cellId={(row, column) => cellId('reservedLeases', row, column)}
          columns={[
            { key: 'hostName', label: 'Host Name' },
            { key: 'hardwareAddress', label: 'MAC Address' },
            { key: 'address', label: 'IP Address' },
            { key: 'comments', label: 'Comments' },
          ]}
          rows={f.reservedLeases}
          onChange={(rows) => set({ reservedLeases: rows })}
          blank={() => ({ hostName: '', hardwareAddress: '', address: '', comments: '' })}
          help="The reserved IP addresses to be assigned to specific clients based on their MAC address. Set a hostname to override the client's hostname."
        />
      </Block>

      <div className={styles.bar}>
        <Button variant="primary" disabled={busy} onClick={save}>
          Save
        </Button>
        <Button onClick={onCancelar}>Cancel</Button>
      </div>
    </div>
  )
}
