import { useId, type ReactNode } from 'react'
import { Alert } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Input } from '../../ui/Field'
import styles from './Settings.module.css'
import frm from '../../ui/Form.module.css'
export { Check } from '../../ui/Check'

/*
Las piezas con las que se dibujan las nueve sub-pestañas.

Upstream mete cada grupo de campos en un `div.well` SIN título. El rediseño le
pone cabecera en mayúsculas pequeñas: son los mismos campos, en el mismo orden y
en la misma sub-pestaña, sólo agrupados a la vista. Los títulos se toman del
`id` del `well` de upstream (`divSettingsGeneralRateLimiting` -> «Rate
Limiting») para no inventarse taxonomías nuevas.

Los avisos de upstream son `<p><b>Note!</b> …</p>` en negrita dentro del flujo.
Aquí pasan a bloque con color: `Warning!` en ámbar, `Note!` en azul.
*/

export function Block({ title, children }: { title: string; children: ReactNode }) {
  return (
    <fieldset className={styles.block}>
      <legend className={styles.blockTitle}>{title}</legend>
      {children}
    </fieldset>
  )
}

export function Row({
  label,
  help,
  children,
}: {
  label: string
  help?: ReactNode
  children: (id: string) => ReactNode
}) {
  const id = useId()
  return (
    <div className={frm.row}>
      <label className={frm.rowLabel} htmlFor={id}>
        {label}
      </label>
      <div className={frm.rowCtl}>
        {children(id)}
        {help && <div className={styles.help}>{help}</div>}
      </div>
    </div>
  )
}

/** Fila cuya etiqueta no gobierna un control concreto (grupos de casillas y de
 *  radios): upstream usa ahí un `<label>` sin `for`. */
export function GroupRow({
  label,
  help,
  children,
}: {
  label: string
  help?: ReactNode
  children: ReactNode
}) {
  return (
    <div className={frm.row}>
      <div className={frm.rowLabel}>{label}</div>
      <div className={frm.rowCtl}>
        <div className={styles.group}>{children}</div>
        {help && <div className={styles.help}>{help}</div>}
      </div>
    </div>
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
  /** Upstream fija 100 px a los campos numéricos y deja los de texto anchos. */
  width?: number | 'wide'
  disabled?: boolean
  maxLength?: number
}) {
  return (
    <Row label={label} help={help}>
      {(id) => (
        <div className={styles.ctlLine}>
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
          {suffix && <span className={styles.suffix}>{suffix}</span>}
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
        <textarea
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


export interface OpcionRadio {
  value: string
  label: string
  help?: ReactNode
}

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
          <label className={styles.check}>
            <input
              type="radio"
              name={name}
              value={o.value}
              checked={value === o.value}
              disabled={disabled}
              onChange={() => onChange(o.value)}
            />
            <span>{o.label}</span>
          </label>
          {o.help && <div className={styles.checkHelp}>{o.help}</div>}
        </div>
      ))}
    </>
  )
}

/** Los avisos de upstream, ya como bloque de color. `Warning!` ámbar, `Note!` azul. */
export function Avisos({ children }: { children: ReactNode }) {
  return <div className={styles.note}>{children}</div>
}

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

/** Texto suelto de upstream que no es ni `Note!` ni `Warning!`. */
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

/** Lista editable: cabecera, una fila por entrada con su «Delete», «Add» debajo. */
export function EditableTable<T>({
  label,
  columns,
  rows,
  onChange,
  nueva,
  help,
  cell,
  disabled,
}: {
  label: string
  columns: string[]
  rows: T[]
  onChange: (rows: T[]) => void
  nueva: () => T
  help?: ReactNode
  cell: (fila: T, i: number, set: (parcial: Partial<T>) => void) => ReactNode[]
  disabled?: boolean
}) {
  return (
    <div className={frm.row}>
      <div className={frm.rowLabel}>{label}</div>
      <div className={frm.rowCtl}>
        <table className={styles.table}>
          <thead>
            <tr>
              {columns.map((c) => (
                <th key={c}>{c}</th>
              ))}
              <th className={styles.tdel} />
            </tr>
          </thead>
          <tbody>
            {rows.map((fila, i) => (
              // Las filas no tienen identidad estable en upstream (se numeran
              // con un aleatorio); el índice es el mismo criterio.
              // eslint-disable-next-line react/no-array-index-key
              <tr key={i}>
                {cell(fila, i, (parcial) =>
                  onChange(rows.map((r, j) => (j === i ? { ...r, ...parcial } : r))),
                ).map((c, j) => (
                  // eslint-disable-next-line react/no-array-index-key
                  <td key={j}>{c}</td>
                ))}
                <td className={styles.tdel}>
                  <Button
                    variant="danger"
                    disabled={disabled}
                    onClick={() => onChange(rows.filter((_, j) => j !== i))}
                  >
                    Delete
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div>
          <Button disabled={disabled} onClick={() => onChange([...rows, nueva()])}>
            Add
          </Button>
        </div>
        {help && <div className={styles.help}>{help}</div>}
      </div>
    </div>
  )
}

export { styles as settingsStyles }
