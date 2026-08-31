import { Button } from '../../../ui/Button'
import { fechaHora } from '../../../lib/fechas'
import { Input } from '../../../ui/Field'
import {
  AreaRow,
  Notices,
  Block,
  Check,
  Coletilla,
  GroupRow,
  Help,
  Note,
  Radios,
  Row,
  TextRow,
  Warning,
  settingsStyles as settings,
  settingsStyles as styles,
} from '../parts'
import { HelpText } from '../../../ui/Form'
import type { PaneProps } from './tipos'

/*
Settings > Blocking (index.html:2066-2190).

This is where the screen's only cascading enablement rule lives
(`updateBlockingState`, main.js:2412): with "Enable Blocking" unchecked, ALL the
sub-tab's controls go off, and "Update Now" additionally requires the URL list
not to be empty.
*/
export interface BlockingExtra {
  /** `temporaryDisableBlockingTill` from `settings/get`. Absent or null = "Not Set". */
  temporaryDisableBlockingTill?: string | null
  /** `blockListNextUpdatedOn`. Absent or null = "Not Scheduled"; past = "Updating Now". */
  blockListNextUpdatedOn?: string | null
  onTemporaryDisable: () => void
  onUpdateNow: () => void
  busy?: boolean
}

export function textoProximaActualizacion(iso: string | null | undefined): string {
  if (iso == null) return 'Not Scheduled'
  return Date.now() < new Date(iso).getTime() ? fechaHora(iso) : 'Updating Now'
}

export function Blocking({ f, set, en, extra }: PaneProps & { extra: BlockingExtra }) {
  const off = !en.blocking

  // No legend: it repeated the panel's title.
  return (
    <Block>
      <GroupRow label="Blocking">
        <Check
          toggle
          label="Enable Blocking"
          checked={f.enableBlocking}
          onChange={(v) => set({ enableBlocking: v })}
          help="Sets the DNS Server to block domain names using Blocked Zone and Block List Zone."
        />
        <Check
          toggle
          label="Allow TXT Blocking Report"
          checked={f.allowTxtBlockingReport}
          onChange={(v) => set({ allowTxtBlockingReport: v })}
          disabled={off}
          help="Specifies if the DNS Server should respond with TXT records containing a blocked domain report for TXT type requests. This option also enables Extended DNS Error blocked domain report in response for requests that support EDNS."
        />
      </GroupRow>

      <Row label="Blocking Temporarily Disabled Till">
        {(id) => (
          <div className={styles.stack}>
            <div className={styles.val}>
              {extra.temporaryDisableBlockingTill == null
                ? 'Not Set'
                : fechaHora(extra.temporaryDisableBlockingTill)}
            </div>
            <div className={settings.enLinea}>
              <Input
                id={id}
                type="number"
                placeholder="minutes"
                style={{ width: 100 }}
                disabled={off}
                value={f.temporaryDisableBlockingMinutes}
                onChange={(e) => set({ temporaryDisableBlockingMinutes: e.target.value })}
              />
              <Coletilla>minutes</Coletilla>
            </div>
            <div>
              <Button disabled={off || extra.busy} onClick={extra.onTemporaryDisable}>
                Temporary Disable Now
              </Button>
            </div>
          </div>
        )}
      </Row>

      <AreaRow
        label="Blocking Bypass List"
        value={f.blockingBypassList}
        onChange={(v) => set({ blockingBypassList: v })}
        disabled={off}
        help="Enter IP addresses or network addresses one below another that are allowed to bypass blocking."
      />

      <GroupRow label="Blocking Type">
        <Radios
          name="rdBlockingType"
          value={f.blockingType}
          onChange={(v) => set({ blockingType: v })}
          disabled={off}
          options={[
            {
              value: 'AnyAddress',
              label: 'ANY Address',
              help: (
                <>
                  Uses <code>0.0.0.0</code> and <code>::</code> IP addresses for blocked domain
                  names.
                </>
              ),
            },
            {
              value: 'NxDomain',
              label: 'NX Domain (recommended)',
              help: (
                <>
                  Uses <code>NX Domain</code> response for blocked domain names.
                </>
              ),
            },
            {
              value: 'CustomAddress',
              label: 'Custom Address',
              help: 'Uses custom IP addresses provided below for blocked domain names.',
            },
          ]}
        />
      </GroupRow>

      <AreaRow
        label="Custom Blocking Addresses (IP Address)"
        value={f.customBlockingAddresses}
        onChange={(v) => set({ customBlockingAddresses: v })}
        disabled={!en.customBlockingAddresses}
      />

      <TextRow
        label="Blocking Answer TTL"
        value={f.blockingAnswerTtl}
        onChange={(v) => set({ blockingAnswerTtl: v })}
        placeholder="ttl"
        suffix="seconds (default 30)"
        help="The TTL value in seconds that must be used for the records in a blocking response. This is the TTL value that the client will use to cache the blocking response."
      />

      <AreaRow
        label="Allow / Block List URLs"
        value={f.blockListUrls}
        onChange={(v) => set({ blockListUrls: v })}
        rows={7}
        disabled={off}
        help={
          <>
            <p>
              Enter block list URL one below another in the above text field or use the Quick Add
              list to add known block list URLs.
            </p>
            <p>
              For directly using block list files saved on this server, use the <code>file://</code>{' '}
              formatted URL path. For example, on Linux the URL should look like{' '}
              <code>file:///home/folder/myblocklist.txt</code> and on Windows it should look like{' '}
              <code>file:///c:/folder/myblocklist.txt</code>.
            </p>
            <p>
              Add <code>!</code> character at the start of an URL to make it an allow list URL. This
              option must not be used with allow lists that use <code>Adblock Plus</code> format.
            </p>
            <p>
              Begin a line with <code>#</code> character at the start to use it for comments.
            </p>
          </>
        }
      />

      <TextRow
        label="Block List Update Interval"
        type="number"
        value={f.blockListUpdateIntervalHours}
        onChange={(v) => set({ blockListUpdateIntervalHours: v })}
        placeholder="hours"
        suffix="hours (valid range 0-168; default 24; set 0 to disable)"
        disabled={off}
        help="The interval in hours to automatically download and update the block lists."
      />

      <GroupRow label="Block List Next Update On">
        <div className={styles.inline}>
          <span className={styles.val}>
            {textoProximaActualizacion(extra.blockListNextUpdatedOn)}
          </span>
          <Button
            disabled={!en.actualizarListasAhora || extra.busy}
            onClick={extra.onUpdateNow}
          >
            Update Now
          </Button>
        </div>
        <HelpText>
          Click the 'Update Now' button to reset the next update schedule and force download and
          update of the block lists.
        </HelpText>
      </GroupRow>

      <Notices>
        <Note>
          The DNS Server will use the data returned by the block list URLs to update the block list
          zone automatically. The expected file format is standard <code>hosts</code> file format,
          plain text file containing list of domains to block, wildcard block list file format, or{' '}
          <code>Adblock Plus</code> file format.
        </Note>
        <Warning>
          The DNS Server loads all block lists in memory and thus it is expected that the server is
          provisioned with sufficient amount of memory to avoid out of memory issues. On average, 1
          million domain names in block list take about 300 MB of memory. The block list update
          process requires additional memory to load the newly downloaded block lists before it
          replaces the previously loaded block lists in memory.
        </Warning>
        <Note>
          To customize the Quick Add drop down list, read the instructions given in the{' '}
          <code>www/json/readme.txt</code> file found in the installation folder.
        </Note>
      </Notices>
      <Help href="https://blog.technitium.com/2018/10/blocking-internet-ads-using-dns-sinkhole.html">
        Help: Blocking Internet Ads Using DNS Sinkhole
      </Help>
    </Block>
  )
}
