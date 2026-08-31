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
Las piezas del formulario-de-panel. Ver `Ajustes.module.css` para por qué viven
aquí y no dentro de Settings o de DHCP.

Upstream mete cada grupo de campos en un `div.well` SIN título (index.html:2565
y siguientes). El rediseño le pone cabecera en versalitas: mismos campos, mismo
orden, sólo agrupados a la vista. Los títulos salen del `id` del `well`
(`divSettingsGeneralRateLimiting` -> «Rate Limiting») para no inventar
taxonomías nuevas.
*/

/*
El título es opcional a propósito.

Cinco paneles repetían su propio nombre como leyenda del primer bloque —TSIG,
Recursion, Blocking, Logging y SSO—, y en tres de ellos era la ÚNICA leyenda,
así que no agrupaba nada: sólo repetía. En SSO llegaba a decirse cuatro veces
seguidas antes del primer control. Sin `title` el panel sigue agrupando: lo que
desaparece es el eco.
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
  /** Upstream fija 80-100 px a los campos numéricos y deja anchos los de texto. */
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

/** La coletilla que sigue a un control: «seconds», «MB», «(0 to disable)». */
export function Coletilla({ children }: { children: ReactNode }) {
  return <span className={texto.coletilla}>{children}</span>
}

export interface OpcionRadio {
  value: string
  label: string
  help?: ReactNode
}

/*
El grupo de radios. Comparte fila y ayuda con `ui/Check`: son el mismo control
con distinta cardinalidad, y cuando cada pantalla se escribía la suya la ayuda
de un radio y la de una casilla no caían en el mismo borde izquierdo.
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

/** Varios bloques sueltos con la sangría del cuerpo del panel. */
export function Avisos({ children }: { children: ReactNode }) {
  return <div className={styles.avisos}>{children}</div>
}

/*
Los avisos de upstream son `<p><b>Note!</b> …</p>` en negrita dentro del flujo.
Aquí pasan a bloque con color: `Warning!` ámbar, `Note!` azul. Van siempre
dentro de un `Avisos`, que es quien pone la sangría — cuando la ponía el propio
aviso en una pantalla y no en la otra, el mismo «Note!» salía metido en DHCP y a
ras en Settings.
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
Lista editable: cabecera, una fila por entrada con su «Delete», «Add» debajo.
Upstream pone el «Add» en la cabecera; aquí va abajo, porque una cabecera de
tabla con un botón dentro no se puede etiquetar.

Había dos, y habían dejado de ser copias: la de DHCP declaraba las columnas y
generaba sola el nombre y el `id` de cada celda; la de Settings recibía las
celdas ya construidas, así que cada sitio de llamada se escribía su propio
`aria-label` a mano y ninguno tenía `id`. Gana la declarativa, con una salida
(`render`) para la única celda que no es un campo de texto.

El nombre accesible es `«<tabla> <fila> <columna>»`. Es único por construcción;
el otro esquema —`«<columna> <fila>»`— obligaba a desambiguar las columnas a
mano, y de ahí salió un `aria-label` «IPv4 UDP Limit» sobre una cabecera que
decía «UDP Limit».

El `id` determinista existe porque el aviso de validación de upstream dice
literalmente «the text field in focus»: sin poder enfocar la celda que falla, el
aviso no se puede resolver.
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
            // Las filas no tienen identidad estable en upstream: se numeran con
            // un aleatorio. El índice es el mismo criterio.
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
      {/* Sin filas, la tabla enseñaba las cabeceras y nada debajo: en blanco no
          dice «no hay ninguna», dice «no lo sé». */}
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
