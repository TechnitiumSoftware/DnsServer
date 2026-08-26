import { useId, type ReactNode } from 'react'
import { Alert } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { Input } from '../../ui/Field'
import styles from './Dhcp.module.css'
import { Empty } from '../../ui/Empty'
import frm from '../../ui/Form.module.css'

/*
Las piezas del formulario de scope. Son las mismas que usa Settings —bloque con
título, fila etiqueta/control, casilla con su explicación debajo y tabla
editable—, pero viven aquí y no se importan de allí: la fase 6 es de otro
agente y acoplar dos pantallas por sus componentes de presentación convierte
cualquier retoque de Settings en un cambio en DHCP.

Upstream mete cada grupo de campos en un `div.well` SIN título (index.html:2565
y siguientes). El rediseño le pone cabecera en mayúsculas pequeñas: mismos
campos, mismo orden, sólo agrupados a la vista.
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

/** Fila cuya etiqueta no gobierna un control concreto (grupos de casillas y
 *  tablas): upstream usa ahí un `<label>` cuyo `for` apunta a un contenedor. */
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
}: {
  label: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
  suffix?: string
  help?: ReactNode
  type?: 'text' | 'number'
  /** Upstream fija 80-100 px a los campos numéricos y deja anchos los de texto. */
  width?: number | 'wide'
  disabled?: boolean
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
  rows = 2,
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

export function Check({
  label,
  checked,
  onChange,
  help,
  disabled,
}: {
  label: string
  checked: boolean
  onChange: (v: boolean) => void
  help?: ReactNode
  disabled?: boolean
}) {
  return (
    <div>
      <label className={styles.check}>
        <input
          type="checkbox"
          checked={checked}
          disabled={disabled}
          onChange={(e) => onChange(e.target.checked)}
        />
        <span>{label}</span>
      </label>
      {help && <div className={styles.checkHelp}>{help}</div>}
    </div>
  )
}

export function Warning({ children }: { children: ReactNode }) {
  return (
    <div className={styles.note}>
      <Alert type="warning" title="Warning!">
        {children}
      </Alert>
    </div>
  )
}

export function Note({ children }: { children: ReactNode }) {
  return (
    <div className={styles.note}>
      <Alert type="info" title="Note!">
        {children}
      </Alert>
    </div>
  )
}

export interface Columna<T> {
  key: keyof T & string
  label: string
  type?: 'text' | 'number'
  min?: number
  max?: number
}

/*
Tabla editable. Upstream pone el botón «Add» en la cabecera y el «Delete» al
final de cada fila; aquí el «Add» va debajo, igual que en Settings, porque una
cabecera de tabla con un botón dentro no se puede etiquetar.

Cada celda lleva un `id` determinista (`dhcp-<tabla>-<fila>-<columna>`) porque
el aviso de validación de upstream dice literalmente «the text field in focus»:
sin poder enfocar la celda que falla, el aviso no se puede resolver.
*/
export function EditableTable<T extends Record<string, string>>({
  tabla,
  label,
  columnas,
  filas,
  onChange,
  nueva,
  help,
  idCelda,
}: {
  tabla: string
  label: string
  columnas: Columna<T>[]
  filas: T[]
  onChange: (filas: T[]) => void
  nueva: () => T
  help?: ReactNode
  idCelda: (tabla: string, fila: number, columna: string) => string
}) {
  return (
    <div className={frm.row}>
      <div className={frm.rowLabel}>{label}</div>
      <div className={frm.rowCtl}>
        <table className={styles.editable}>
          <thead>
            <tr>
              {columnas.map((c) => (
                <th key={c.key}>{c.label}</th>
              ))}
              <th className={styles.tdel} />
            </tr>
          </thead>
          <tbody>
            {filas.map((fila, i) => (
              // Las filas no tienen identidad estable en upstream: se numeran
              // con un aleatorio. El índice es el mismo criterio.
              // eslint-disable-next-line react/no-array-index-key
              <tr key={i}>
                {columnas.map((c) => {
                  const id = idCelda(tabla, i, c.key)
                  return (
                    <td key={c.key}>
                      <Input
                        id={id}
                        aria-label={`${label} ${i + 1} ${c.label}`}
                        type={c.type ?? 'text'}
                        min={c.min}
                        max={c.max}
                        value={fila[c.key]}
                        onChange={(e) =>
                          onChange(
                            filas.map((r, j) => (j === i ? { ...r, [c.key]: e.target.value } : r)),
                          )
                        }
                      />
                    </td>
                  )
                })}
                <td className={styles.tdel}>
                  <Button
                    variant="danger"
                    onClick={() => onChange(filas.filter((_, j) => j !== i))}
                  >
                    Delete
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filas.length === 0 && <Empty compacto>No entries.</Empty>}
        <div>
          <Button onClick={() => onChange([...filas, nueva()])}>Add</Button>
        </div>
        {help && <div className={styles.help}>{help}</div>}
      </div>
    </div>
  )
}

export { styles as dhcpStyles }
