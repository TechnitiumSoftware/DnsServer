import type { ReactElement, SVGProps } from 'react'

/*
El juego de iconos de la consola, dibujado aquí.

Antes eran caracteres Unicode —`▣ ◆ ○ ✓ ⊘ ⊞ ⌕ ⚙ ▤ ☺ ≡ ⓘ`— y eso tiene dos
problemas y medio: cada sistema operativo los pinta con su propia fuente, así
que la consola cambiaba de aspecto según la máquina; no comparten grosor ni
rejilla, porque no son un juego sino doce símbolos sueltos de tablas distintas;
y `☺` para Administration es literalmente una carita sonriente.

No se puede traer una librería: la CSP del servidor es `default-src 'self'` sin
`font-src` (DnsWebService.cs:1969-1975), así que ni CDN ni fuente de iconos. Van
como SVG en línea, que además es lo que permite que hereden el color del texto.

Rejilla de 24, trazo de 1.75 y remates redondos, los mismos para los veintiuno.
*/

const TRAZO = {
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.75,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
} as const

export type NombreIcono =
  | 'dashboard' | 'zones' | 'cache' | 'allowed' | 'blocked' | 'apps'
  | 'dnsclient' | 'settings' | 'dhcp' | 'admin' | 'logs' | 'about'
  | 'chevronAbajo' | 'chevronDerecha' | 'chevronIzquierda'
  | 'primera' | 'ultima' | 'cerrar' | 'menu' | 'mas' | 'orden' | 'atras'

const TRAZADOS: Record<NombreIcono, ReactElement> = {
  // ── Secciones ─────────────────────────────────────────────────────────
  /* Un panel con sus medidas: el cuadro de mando. */
  dashboard: (
    <>
      <rect x="3" y="3" width="7.5" height="8.5" rx="1.5" />
      <rect x="13.5" y="3" width="7.5" height="5" rx="1.5" />
      <rect x="3" y="15" width="7.5" height="6" rx="1.5" />
      <rect x="13.5" y="11" width="7.5" height="10" rx="1.5" />
    </>
  ),
  /* Un árbol de dominio: la raíz y sus ramas. Es lo que es una zona. */
  zones: (
    <>
      <path d="M12 3v5" />
      <path d="M6 21v-3a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v3" />
      <path d="M12 12v4" />
      <circle cx="12" cy="4.5" r="1.5" />
      <circle cx="6" cy="19.5" r="1.5" />
      <circle cx="18" cy="19.5" r="1.5" />
      <circle cx="12" cy="10.5" r="1.5" />
    </>
  ),
  /* Capas apiladas: lo que está guardado a la espera de volver a servirse. */
  cache: (
    <>
      <ellipse cx="12" cy="5.5" rx="8" ry="2.75" />
      <path d="M4 5.5v6c0 1.5 3.6 2.75 8 2.75s8-1.25 8-2.75v-6" />
      <path d="M4 11.5v6c0 1.5 3.6 2.75 8 2.75s8-1.25 8-2.75v-6" />
    </>
  ),
  /* Escudo con visto: lo que pasa. */
  allowed: (
    <>
      <path d="M12 3 5 6v5.5c0 4.2 2.9 8 7 9.5 4.1-1.5 7-5.3 7-9.5V6z" />
      <path d="m9 12 2.2 2.2L15.5 10" />
    </>
  ),
  /* Escudo con aspa: lo que no pasa. */
  blocked: (
    <>
      <path d="M12 3 5 6v5.5c0 4.2 2.9 8 7 9.5 4.1-1.5 7-5.3 7-9.5V6z" />
      <path d="m9.5 9.5 5 5m0-5-5 5" />
    </>
  ),
  /* Un módulo que se enchufa al servidor. */
  apps: (
    <>
      <rect x="4" y="8" width="16" height="12" rx="2" />
      <path d="M9 8V5.5a2.5 2.5 0 0 1 5 0V8" />
      <path d="M9.5 14h5" />
    </>
  ),
  /* Una consulta que sale y una respuesta que vuelve. */
  dnsclient: (
    <>
      <path d="M4 9h11" />
      <path d="m11.5 5.5 3.5 3.5-3.5 3.5" />
      <path d="M20 15H9" />
      <path d="m12.5 11.5-3.5 3.5 3.5 3.5" />
    </>
  ),
  /* Los deslizadores de un panel de ajustes. */
  settings: (
    <>
      <path d="M5 7h9" />
      <path d="M18 7h1" />
      <path d="M5 17h4" />
      <path d="M13 17h6" />
      <circle cx="16" cy="7" r="2" />
      <circle cx="11" cy="17" r="2" />
    </>
  ),
  /* Una asignación: la dirección que se reparte a un equipo. */
  dhcp: (
    <>
      <rect x="3" y="4" width="18" height="9" rx="2" />
      <path d="M7.5 8.5h4" />
      <path d="M12 17v3" />
      <path d="M8 20h8" />
      <path d="M12 13v4" />
    </>
  ),
  /* Una llave: quién puede qué. Ni carita ni persona. */
  admin: (
    <>
      <circle cx="8" cy="12" r="4" />
      <path d="M11.8 11h8.2" />
      <path d="M17 11v3.5" />
      <path d="M20 11v2.5" />
    </>
  ),
  /* Renglones de registro, uno más corto porque el último está a medias. */
  logs: (
    <>
      <path d="M4.5 6.5h15" />
      <path d="M4.5 10.5h15" />
      <path d="M4.5 14.5h15" />
      <path d="M4.5 18.5h8" />
    </>
  ),
  about: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5.5" />
      <path d="M12 7.75v.5" />
    </>
  ),

  // ── Controles ─────────────────────────────────────────────────────────
  chevronAbajo: <path d="m6 9 6 6 6-6" />,
  chevronDerecha: <path d="m9 6 6 6-6 6" />,
  chevronIzquierda: <path d="m15 6-6 6 6 6" />,
  primera: (
    <>
      <path d="m17 6-6 6 6 6" />
      <path d="M7.5 6v12" />
    </>
  ),
  ultima: (
    <>
      <path d="m7 6 6 6-6 6" />
      <path d="M16.5 6v12" />
    </>
  ),
  cerrar: <path d="m6 6 12 12M18 6 6 18" />,
  menu: (
    <>
      <path d="M4 7h16" />
      <path d="M4 12h16" />
      <path d="M4 17h16" />
    </>
  ),
  /* Los tres puntos del menú de una fila. Rellenos, no trazados. */
  mas: (
    <g fill="currentColor" stroke="none">
      <circle cx="12" cy="5.5" r="1.6" />
      <circle cx="12" cy="12" r="1.6" />
      <circle cx="12" cy="18.5" r="1.6" />
    </g>
  ),
  /* La doble punta de una columna ordenable, sin dirección todavía. */
  orden: (
    <>
      <path d="m8 10 4-4 4 4" />
      <path d="m8 14 4 4 4-4" />
    </>
  ),
  atras: (
    <>
      <path d="M19 12H5" />
      <path d="m11 6-6 6 6 6" />
    </>
  ),
}

export function Icono({
  nombre,
  tam = 16,
  ...rest
}: { nombre: NombreIcono; tam?: number } & Omit<SVGProps<SVGSVGElement>, 'ref'>) {
  return (
    <svg
      width={tam}
      height={tam}
      viewBox="0 0 24 24"
      aria-hidden="true"
      focusable="false"
      {...TRAZO}
      {...rest}
    >
      {TRAZADOS[nombre]}
    </svg>
  )
}
