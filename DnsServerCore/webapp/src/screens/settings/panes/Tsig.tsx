import { Select } from '../../../ui/Field'
import { Notices, Block, EditableList, Note } from '../parts'
import type { PaneProps } from './tipos'

/** The dropdown's eight algorithms, with their literal labels (`addTsigKeyRow`,
 *  main.js:2260). A new key's default value is `hmac-sha256`, same as upstream's
 *  "Add" button. */
export const TSIG_ALGORITHMS: { value: string; label: string }[] = [
  { value: 'hmac-md5.sig-alg.reg.int', label: 'HMAC-MD5 (obsolete)' },
  { value: 'hmac-sha1', label: 'HMAC-SHA1' },
  { value: 'hmac-sha256', label: 'HMAC-SHA256 (recommended)' },
  { value: 'hmac-sha256-128', label: 'HMAC-SHA256 (128 bits)' },
  { value: 'hmac-sha384', label: 'HMAC-SHA384' },
  { value: 'hmac-sha384-192', label: 'HMAC-SHA384 (192 bits)' },
  { value: 'hmac-sha512', label: 'HMAC-SHA512' },
  { value: 'hmac-sha512-256', label: 'HMAC-SHA512 (256 bits)' },
]

/* Settings > TSIG (index.html:1770-1792). The shared secret is the ONLY table
   field in the whole console marked `data-optional`: it can be left empty and the
   server generates a strong key. */
export function Tsig({ f, set }: PaneProps) {
  // No legend: it repeated the panel's title.
  return (
    <Block>
      <EditableList
        label="TSIG Keys"
        columns={[
          { key: 'keyName', label: 'Key Name' },
          { key: 'sharedSecret', label: 'Shared Secret' },
          {
            key: 'algorithmName',
            label: 'Algorithm',
            render: (row, set, id, name) => (
              <Select
                id={id}
                aria-label={name}
                value={row.algorithmName}
                onChange={(e) => set({ algorithmName: e.target.value })}
              >
                {TSIG_ALGORITHMS.map((a) => (
                  <option key={a.value} value={a.value}>
                    {a.label}
                  </option>
                ))}
              </Select>
            ),
          },
        ]}
        rows={f.tsigKeys}
        onChange={(rows) => set({ tsigKeys: rows })}
        blank={() => ({ keyName: '', sharedSecret: '', algorithmName: 'hmac-sha256' })}
        help="The shared secret can be a base64 string or a literal string. Keep the shared secret empty if you want to auto generate a strong key."
      />
      <Notices>
        <Note>
          You will need to configure these TSIG keys names for zone transfer in the zone options and
          in the secondary zone SOA record options separately.
        </Note>
      </Notices>
    </Block>
  )
}
