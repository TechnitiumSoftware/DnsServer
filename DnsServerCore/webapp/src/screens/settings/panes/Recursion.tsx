import {
  Avisos,
  Block,
  Check,
  GroupRow,
  Note,
  Radios,
  Row,
  TextRow,
  Warning,
  ajustesStyles as ajustes,
} from '../parts'
import { Textarea } from '../../../ui/Field'
import type { PaneProps } from './tipos'

/*
Settings > Recursion (index.html:1794-1910). Three blocks.

The ACL can only be edited with the fourth option selected (`Use Specified
Network Access Control List (ACL)`); with the other three upstream leaves it
disabled but visible, it does not hide it.
*/
export function Recursion({ f, set, en }: PaneProps) {
  return (
    <>
      {/* No legend: it repeated the panel's title. */}
      <Block>
        <GroupRow label="Recursion">
          <Radios
            name="rdRecursion"
            value={f.recursion}
            onChange={(v) => set({ recursion: v })}
            options={[
              {
                value: 'Deny',
                label: 'Deny Recursion',
                help: 'Disables recursion so that this DNS Server works as authoritative only.',
              },
              {
                value: 'Allow',
                label: 'Allow Recursion',
                help: 'Enables recursion to allow this DNS Server to resolve any domain name.',
              },
              {
                value: 'AllowOnlyForPrivateNetworks',
                label: 'Allow Recursion Only For Private Networks (default)',
                help: 'Select this option if you want to support recursion only on private networks. Any recursive request from a public network will be refused.',
              },
              {
                value: 'UseSpecifiedNetworkACL',
                label: 'Use Specified Network Access Control List (ACL)',
                help: 'Select this option to specify networks that must be allowed or denied recursion.',
              },
            ]}
          />
        </GroupRow>

        <Row
          label="Network Access Control List (ACL)"
          help={
            <>
              Enter IP addresses or network addresses one below another to allow access. Add{' '}
              <code>!</code> character at the start to deny access, e.g.{' '}
              <code>!192.168.10.0/24</code> will deny entire subnet. The ACL is processed in the
              same order its listed. If no networks match, the default policy is to deny all except
              loopback.
            </>
          }
        >
          {(id) => (
            <Textarea
              mono
              id={id}
              className={ajustes.area}
              rows={5}
              spellCheck={false}
              disabled={!en.recursionNetworkACL}
              value={f.recursionNetworkACL}
              onChange={(e) => set({ recursionNetworkACL: e.target.value })}
            />
          )}
        </Row>

        <Avisos>
          <Note>
            Disable recursion if you wish this server to act only as authoritative name server for
            the configured zones.
          </Note>
          <Note>
            You need to have the above recursion option enabled even when you have configured
            Forwarders in Settings and do not want the DNS Server to do recursive resolution. This
            option is not about recursive resolution itself but about the Recursion Desired (RD)
            flag in the incoming DNS requests.
          </Note>
        </Avisos>
      </Block>

      <Block title="Recursive Resolver">
        <GroupRow label="Recursive Resolver">
          <Check
            conmutador
            label="Randomize Name"
            checked={f.randomizeName}
            onChange={(v) => set({ randomizeName: v })}
            help={
              <>
                Enables{' '}
                <a
                  href="https://datatracker.ietf.org/doc/draft-vixie-dnsext-dns0x20/"
                  target="_blank"
                  rel="noreferrer"
                >
                  QNAME case randomization
                </a>{' '}
                when using UDP as the transport protocol to improve security.
              </>
            }
          />
          <Check
            conmutador
            label="QNAME Minimization"
            checked={f.qnameMinimization}
            onChange={(v) => set({ qnameMinimization: v })}
            help={
              <>
                Enables{' '}
                <a href="https://datatracker.ietf.org/doc/rfc9156/" target="_blank" rel="noreferrer">
                  QNAME minimization
                </a>{' '}
                for recursive resolution to improve privacy.
              </>
            }
          />
          <Check
            conmutador
            label="Locally Served DNS Zones"
            checked={f.locallyServedDnsZones}
            onChange={(v) => set({ locallyServedDnsZones: v })}
            help={
              <>
                Enables{' '}
                <a href="https://datatracker.ietf.org/doc/rfc6303/" target="_blank" rel="noreferrer">
                  Locally Served DNS Zones
                </a>{' '}
                and{' '}
                <a href="https://datatracker.ietf.org/doc/rfc6761/" target="_blank" rel="noreferrer">
                  Special-Use Domain Names
                </a>{' '}
                for recursive resolution to avoid leakage of queries and reduce load on the root
                servers. Create a Stub or Conditional Forwarder zone for each domain name that you
                want to resolve externally.
              </>
            }
          />
        </GroupRow>
        <Avisos>
          <Warning>
            Enabling the <b>Randomize Name</b> option may cause some domain names to fail to resolve
            due to their name servers dropping the requests or sending the QNAME in response with a
            different case causing mismatch. The DNS Server can already detect DNS spoofing attack
            attempts and switch to TCP protocol automatically so its safe to not use this feature.
          </Warning>
        </Avisos>
      </Block>

      <Block title="Resolver Options">
        <TextRow
          label="Resolver Retries"
          type="number"
          value={f.resolverRetries}
          onChange={(v) => set({ resolverRetries: v })}
          placeholder="retries"
          suffix="(valid range 1-10; default 2)"
          help="The total number of retries the recursive resolver must do per name server."
        />
        <TextRow
          label="Resolver Timeout"
          type="number"
          value={f.resolverTimeout}
          onChange={(v) => set({ resolverTimeout: v })}
          placeholder="timeout"
          suffix="milliseconds (valid range 1000-10000; default 1500)"
          help="The amount of time the recursive resolver must wait between retries."
        />
        <TextRow
          label="Resolver Concurrency"
          type="number"
          value={f.resolverConcurrency}
          onChange={(v) => set({ resolverConcurrency: v })}
          placeholder="count"
          suffix="(valid range 1-4; default 2)"
          help="The number of concurrent requests that should be sent by the recursive resolver to the name servers."
        />
        <TextRow
          label="Resolver Max Stack Count"
          type="number"
          value={f.resolverMaxStackCount}
          onChange={(v) => set({ resolverMaxStackCount: v })}
          placeholder="count"
          suffix="(valid range 10-30; default 16)"
          help="The maximum stack count the recursive resolver must use for resolving a domain name."
        />
        <Avisos>
          <Note>
            The DNS Server supports EDNS and thus all outbound recursive resolution requests will
            have an OPT record for it in the additional section. If a name server does not respond
            to a request containing OPT record, the recursive resolver will retry again without the
            OPT record when possible. This means that the number of retries attempted per name
            server can be Resolver Retries value multiplied by two for certain cases.
          </Note>
          <Note>
            The DNS Server uses Epsilon-Greedy machine learning algorithm and will automatically
            learn which of the name servers are answering faster without errors and will use those
            name servers most of the time. Since each domain name has a different set of name
            servers, it may take a while before the algorithm learns about them.
          </Note>
        </Avisos>
      </Block>
    </>
  )
}
