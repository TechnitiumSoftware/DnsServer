import styles from './Segmentado.module.css'

/*
Elegir uno de un puñado de valores, con todos a la vista. Ver el módulo de
estilos para por qué existe.

`comoPestanas` cambia la semántica, no el aspecto: un grupo de pestañas gobierna
un panel y se anuncia con `role="tab"` y `aria-selected`; un grupo de opciones
—el periodo del Dashboard— son botones de estado y se anuncian con
`aria-pressed`. Se parecen y no son lo mismo, así que lo decide quien lo usa.
*/
export function Segmentado<T extends string>({
  opciones,
  activa,
  onElegir,
  etiqueta,
  comoPestanas = false,
}: {
  opciones: { id: T; etiqueta: string }[]
  activa: T
  onElegir: (id: T) => void
  /** Nombre del grupo, para quien no ve la pantalla. */
  etiqueta: string
  comoPestanas?: boolean
}) {
  return (
    <div
      className={styles.seg}
      role={comoPestanas ? 'tablist' : 'group'}
      aria-label={etiqueta}
    >
      {opciones.map((o) => (
        <button
          key={o.id}
          type="button"
          className={styles.opcion}
          role={comoPestanas ? 'tab' : undefined}
          aria-selected={comoPestanas ? o.id === activa : undefined}
          aria-pressed={comoPestanas ? undefined : o.id === activa}
          onClick={() => onElegir(o.id)}
        >
          {o.etiqueta}
        </button>
      ))}
    </div>
  )
}
