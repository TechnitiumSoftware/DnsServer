import { Select } from '../../../ui/Field'
import { Avisos, Block, EditableTable, Note } from '../parts'
import type { PaneProps } from './tipos'

/** Los ocho algoritmos del desplegable, con su etiqueta literal
 *  (`addTsigKeyRow`, main.js:2260). El valor por defecto de una clave nueva es
 *  `hmac-sha256`, igual que el botón «Add» de upstream. */
export const ALGORITMOS_TSIG: { value: string; label: string }[] = [
  { value: 'hmac-md5.sig-alg.reg.int', label: 'HMAC-MD5 (obsolete)' },
  { value: 'hmac-sha1', label: 'HMAC-SHA1' },
  { value: 'hmac-sha256', label: 'HMAC-SHA256 (recommended)' },
  { value: 'hmac-sha256-128', label: 'HMAC-SHA256 (128 bits)' },
  { value: 'hmac-sha384', label: 'HMAC-SHA384' },
  { value: 'hmac-sha384-192', label: 'HMAC-SHA384 (192 bits)' },
  { value: 'hmac-sha512', label: 'HMAC-SHA512' },
  { value: 'hmac-sha512-256', label: 'HMAC-SHA512 (256 bits)' },
]

/* Settings > TSIG (index.html:1770-1792). El secreto compartido es el ÚNICO
   campo de tabla de toda la consola marcado `data-optional`: se puede dejar
   vacío y el servidor genera una clave fuerte. */
export function Tsig({ f, set }: PaneProps) {
  // Sin leyenda: repetía el título del panel.
  return (
    <Block>
      <EditableTable
        label="TSIG Keys"
        columnas={[
          { key: 'keyName', label: 'Key Name' },
          { key: 'sharedSecret', label: 'Shared Secret' },
          {
            key: 'algorithmName',
            label: 'Algorithm',
            render: (fila, set, id, nombre) => (
              <Select
                id={id}
                aria-label={nombre}
                value={fila.algorithmName}
                onChange={(e) => set({ algorithmName: e.target.value })}
              >
                {ALGORITMOS_TSIG.map((a) => (
                  <option key={a.value} value={a.value}>
                    {a.label}
                  </option>
                ))}
              </Select>
            ),
          },
        ]}
        filas={f.tsigKeys}
        onChange={(filas) => set({ tsigKeys: filas })}
        nueva={() => ({ keyName: '', sharedSecret: '', algorithmName: 'hmac-sha256' })}
        help="The shared secret can be a base64 string or a literal string. Keep the shared secret empty if you want to auto generate a strong key."
      />
      <Avisos>
        <Note>
          You will need to configure these TSIG keys names for zone transfer in the zone options and
          in the secondary zone SOA record options separately.
        </Note>
      </Avisos>
    </Block>
  )
}
