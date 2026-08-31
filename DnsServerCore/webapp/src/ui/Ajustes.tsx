import { type ReactNode } from 'react'
import { Alert } from './Alert'
import { Button } from './Button'
import { Empty } from './Empty'
import { Input, Textarea } from './Field'
import { Ayuda, GroupRow, Row } from './Form'
import { Panel } from './Panel'
import { TablaEditable } from './TablaEditable'
import check from './Check.module.css'
import texto from './texto.module.css'
import styles from './Ajustes.module.css'

/*
The pieces of the panel-form kit. See `Ajustes.module.css` for why they live
here and not inside Settings or DHCP.

Upstream puts each group of fields in a `div.well` with NO title (index.html:2565
onwards). The redesign gives it a small-caps header: same fields, same order,
just visually grouped. The titles come from the `well`'s `id`
(`divSettingsGeneralRateLimiting` -> "Rate Limiting") so as not to invent new
taxonomies.
*/

/*
The title is optional on purpose.

Five panels repeated their own name as the legend of the first block —TSIG,
Recursion, Blocking, Logging and SSO— and in three of them it was the ONLY
legend, so it grouped nothing: it just repeated. In SSO it got said four times in
a row before the first control. Without `title` the panel still groups: what
disappears is the echo.
*/
export function Block({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <Panel titulo={title} className={styles.block} agrupa>
      {children}
    </Panel>
  )
}

export function TextRow({
  label,
  value,
  onChange,
  placeholder,
  suffix,
  help,
  type = 'text',
  width = 100,
  disabled,
  maxLength,
}: {
  label: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
  suffix?: string
  help?: ReactNode
  type?: 'text' | 'number' | 'password'
  /** Upstream pins numeric fields at 80-100 px and leaves text fields wide. */
  width?: number | 'wide'
  disabled?: boolean
  maxLength?: number
}) {
  return (
    <Row label={label} help={help}>
      {(id) => (
        <div className={styles.enLinea}>
          <Input
            id={id}
            type={type}
            value={value}
            placeholder={placeholder}
            disabled={disabled}
            maxLength={maxLength}
            onChange={(e) => onChange(e.target.value)}
            style={width === 'wide' ? { width: '100%', maxWidth: 420 } : { width }}
          />
          {suffix && <Coletilla>{suffix}</Coletilla>}
        </div>
      )}
    </Row>
  )
}

export function AreaRow({
  label,
  value,
  onChange,
  rows = 3,
  help,
  disabled,
}: {
  label: string
  value: string
  onChange: (v: string) => void
  rows?: number
  help?: ReactNode
  disabled?: boolean
}) {
  return (
    <Row label={label} help={help}>
      {(id) => (
        <Textarea
          mono
          id={id}
          className={styles.area}
          rows={rows}
          spellCheck={false}
          disabled={disabled}
          value={value}
          onChange={(e) => onChange(e.target.value)}
        />
      )}
    </Row>
  )
}

/** The suffix that follows a control: "seconds", "MB", "(0 to disable)". */
export function Coletilla({ children }: { children: ReactNode }) {
  return <span className={texto.coletilla}>{children}</span>
}

export interface OpcionRadio {
  value: string
  label: string
  help?: ReactNode
}

/*
The radio group. It shares its row and its help with `ui/Check`: they are the
same control with different cardinality, and when each screen wrote its own, a
radio's help and a checkbox's help did not land on the same left edge.
*/
export function Radios({
  name,
  value,
  options,
  onChange,
  disabled,
}: {
  name: string
  value: string
  options: OpcionRadio[]
  onChange: (v: string) => void
  disabled?: boolean
}) {
  return (
    <>
      {options.map((o) => (
        <div key={o.value}>
          <label className={check.check}>
            <input
              type="radio"
              name={name}
              value={o.value}
              checked={value === o.value}
              disabled={disabled}
              onChange={() => onChange(o.value)}
            />
            <span className={check.texto}>{o.label}</span>
          </label>
          {o.help && <div className={check.ayuda}>{o.help}</div>}
        </div>
      ))}
    </>
  )
}

/** Several loose blocks carrying the panel body's inset. */
export function Avisos({ children }: { children: ReactNode }) {
  return <div className={styles.avisos}>{children}</div>
}

/*
Upstream's alerts are `<p><b>Note!</b> …</p>` in bold, inline. Here they become
a coloured block: `Warning!` amber, `Note!` blue. They always go inside an
`Avisos`, which is what supplies the inset — when the alert supplied it itself on
one screen and not the other, the same "Note!" came out indented in DHCP and flush
in Settings.
*/
export function Warning({ children }: { children: ReactNode }) {
  return (
    <Alert type="warning" title="Warning!">
      {children}
    </Alert>
  )
}

export function Note({ children }: { children: ReactNode }) {
  return (
    <Alert type="info" title="Note!">
      {children}
    </Alert>
  )
}

/** Loose upstream text that is neither `Note!` nor `Warning!`. */
export function Plain({ children }: { children: ReactNode }) {
  return <div className={styles.plain}>{children}</div>
}

export function Help({ href, children }: { href: string; children: ReactNode }) {
  return (
    <div className={styles.link}>
      <a href={href} target="_blank" rel="noreferrer">
        {children}
      </a>
    </div>
  )
}

export function Pre({ children }: { children: ReactNode }) {
  return <pre className={styles.pre}>{children}</pre>
}

export interface Columna<T> {
  key: keyof T & string
  label: string
  type?: 'text' | 'number'
  min?: number
  max?: number
  /** Cuando la celda no es un campo de texto: el desplegable de algoritmo de TSIG. */
  render?: (fila: T, set: (parcial: Partial<T>) => void, id: string, nombre: string) => ReactNode
}

/*
Editable list: a header, one row per entry with its "Delete", and "Add" below.
Upstream puts the "Add" in the header; here it goes underneath, because a table
header with a button inside cannot be labelled.

There were two, and they had stopped being copies: DHCP's declared its columns and
generated each cell's name and `id` by itself; Settings' received the cells
already built, so every call site wrote its own `aria-label` by hand and none had
an `id`. The declarative one wins, with an escape hatch (`render`) for the single
cell that is not a text field.

The accessible name is `"<table> <row> <column>"`. It is unique by construction;
the other scheme —`"<column> <row>"`— forced you to disambiguate the columns by
hand, and out of that came an `aria-label` of "IPv4 UDP Limit" over a header that
said "UDP Limit".

The deterministic `id` exists because upstream's validation alert says literally
"the text field in focus": without being able to focus the failing cell, the alert
cannot be resolved.
*/
export function EditableTable<T extends Record<string, string>>({
  label,
  columnas,
  filas,
  onChange,
  nueva,
  help,
  disabled,
  idCelda,
}: {
  label: string
  columnas: Columna<T>[]
  filas: T[]
  onChange: (filas: T[]) => void
  nueva: () => T
  help?: ReactNode
  disabled?: boolean
  idCelda?: (fila: number, columna: string) => string
}) {
  return (
    <GroupRow label={label}>
      <TablaEditable
        className={styles.editable}
        cabecera={
          <>
            {columnas.map((c) => (
              <th key={c.key}>{c.label}</th>
            ))}
            <th className={styles.tdel} />
          </>
        }
      >
        {filas.map((fila, i) => {
          const set = (parcial: Partial<T>) =>
            onChange(filas.map((r, j) => (j === i ? { ...r, ...parcial } : r)))
          return (
            // Rows have no stable identity in upstream: they are numbered with
            // a random number. The index is the same criterion.
            // eslint-disable-next-line react/no-array-index-key
            <tr key={i}>
              {columnas.map((c) => {
                const id = idCelda?.(i, c.key)
                const nombre = `${label} ${i + 1} ${c.label}`
                return (
                  <td key={c.key}>
                    {c.render ? (
                      c.render(fila, set, id ?? '', nombre)
                    ) : (
                      <Input
                        id={id}
                        aria-label={nombre}
                        type={c.type ?? 'text'}
                        min={c.min}
                        max={c.max}
                        disabled={disabled}
                        value={fila[c.key]}
                        onChange={(e) => set({ [c.key]: e.target.value } as Partial<T>)}
                      />
                    )}
                  </td>
                )
              })}
              <td className={styles.tdel}>
                <Button
                  variant="danger"
                  disabled={disabled}
                  onClick={() => onChange(filas.filter((_, j) => j !== i))}
                >
                  Delete
                </Button>
              </td>
            </tr>
          )
        })}
      </TablaEditable>
      {/* With no rows, the table showed the headers and nothing beneath: blank
          does not say "there are none", it says "I do not know". */}
      {filas.length === 0 && <Empty compacto>No entries.</Empty>}
      <div>
        <Button disabled={disabled} onClick={() => onChange([...filas, nueva()])}>
          Add
        </Button>
      </div>
      {help && <Ayuda>{help}</Ayuda>}
    </GroupRow>
  )
}

export { Check } from './Check'
export { Ayuda, GroupRow, Row }
export { styles as ajustesStyles }
