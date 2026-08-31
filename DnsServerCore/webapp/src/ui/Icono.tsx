import type { ReactElement, SVGProps } from 'react'

/*
The console's icon set, drawn here.

They used to be Unicode characters —`▣ ◆ ○ ✓ ⊘ ⊞ ⌕ ⚙ ▤ ☺ ≡ ⓘ`— and that has two
and a half problems: every operating system paints them with its own font, so the
console changed appearance depending on the machine; they share neither stroke
weight nor grid, because they are not a set but twelve loose symbols from
different tables; and `☺` for Administration is literally a smiley face.

A library cannot be brought in: the server's CSP is `default-src 'self'` with no
`font-src` (DnsWebService.cs:1969-1975), so no CDN and no icon font. They go as
inline SVG, which is also what lets them inherit the text colour.

24 grid, 1.75 stroke and round caps, the same for all twenty-one.
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
  | 'primera' | 'ultima' | 'cerrar' | 'menu' | 'mas' | 'orden' | 'atras' | 'check'
  | 'editar' | 'energia' | 'ficha' | 'convertir'

const TRAZADOS: Record<NombreIcono, ReactElement> = {
  // ── Secciones ─────────────────────────────────────────────────────────
  /* A panel with its readings: the dashboard. */
  dashboard: (
    <>
      <rect x="3" y="3" width="7.5" height="8.5" rx="1.5" />
      <rect x="13.5" y="3" width="7.5" height="5" rx="1.5" />
      <rect x="3" y="15" width="7.5" height="6" rx="1.5" />
      <rect x="13.5" y="11" width="7.5" height="10" rx="1.5" />
    </>
  ),
  /* A domain tree: the root and its branches. That is what a zone is. */
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
  /* Stacked layers: what is stored waiting to be served again. */
  cache: (
    <>
      <ellipse cx="12" cy="5.5" rx="8" ry="2.75" />
      <path d="M4 5.5v6c0 1.5 3.6 2.75 8 2.75s8-1.25 8-2.75v-6" />
      <path d="M4 11.5v6c0 1.5 3.6 2.75 8 2.75s8-1.25 8-2.75v-6" />
    </>
  ),
  /* Shield with a tick: what gets through. */
  allowed: (
    <>
      <path d="M12 3 5 6v5.5c0 4.2 2.9 8 7 9.5 4.1-1.5 7-5.3 7-9.5V6z" />
      <path d="m9 12 2.2 2.2L15.5 10" />
    </>
  ),
  /* Shield with a cross: what does not. */
  blocked: (
    <>
      <path d="M12 3 5 6v5.5c0 4.2 2.9 8 7 9.5 4.1-1.5 7-5.3 7-9.5V6z" />
      <path d="m9.5 9.5 5 5m0-5-5 5" />
    </>
  ),
  /* A module that plugs into the server. */
  apps: (
    <>
      <rect x="4" y="8" width="16" height="12" rx="2" />
      <path d="M9 8V5.5a2.5 2.5 0 0 1 5 0V8" />
      <path d="M9.5 14h5" />
    </>
  ),
  /* A query going out and an answer coming back. */
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
  /* An assignment: the address handed out to a machine. */
  dhcp: (
    <>
      <rect x="3" y="4" width="18" height="9" rx="2" />
      <path d="M7.5 8.5h4" />
      <path d="M12 17v3" />
      <path d="M8 20h8" />
      <path d="M12 13v4" />
    </>
  ),
  /* A key: who can do what. Not a smiley, not a person. */
  admin: (
    <>
      <circle cx="8" cy="12" r="4" />
      <path d="M11.8 11h8.2" />
      <path d="M17 11v3.5" />
      <path d="M20 11v2.5" />
    </>
  ),
  /* Log lines, one shorter because the last one is mid-write. */
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
  check: <path d="m20 6-11 11-5-5" />,

  // ── Acciones de fila ──────────────────────────────────────────────────
  editar: (
    <>
      <path d="M11 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-5" />
      <path d="M18.5 2.5a2.12 2.12 0 0 1 3 3L12 15l-4 1 1-4z" />
    </>
  ),
  /* Power on and off: the same symbol for both states, because the "Status"
     column already says which one it is in. */
  energia: (
    <>
      <path d="M12 3v9" />
      <path d="M18.4 6.6a9 9 0 1 1-12.8 0" />
    </>
  ),
  /* La ficha de alguien: «View Details». */
  ficha: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <circle cx="9" cy="10" r="2" />
      <path d="M5.5 17c.7-1.8 2-2.5 3.5-2.5s2.8.7 3.5 2.5" />
      <path d="M15 9.5h3.5" />
      <path d="M15 13h3.5" />
    </>
  ),
  convertir: (
    <>
      <path d="M4 8h13" />
      <path d="m14 5 3 3-3 3" />
      <path d="M20 16H7" />
      <path d="m10 13-3 3 3 3" />
    </>
  ),
  menu: (
    <>
      <path d="M4 7h16" />
      <path d="M4 12h16" />
      <path d="M4 17h16" />
    </>
  ),
  /* The three dots of a row menu. Filled, not stroked. */
  mas: (
    <g fill="currentColor" stroke="none">
      <circle cx="12" cy="5.5" r="1.6" />
      <circle cx="12" cy="12" r="1.6" />
      <circle cx="12" cy="18.5" r="1.6" />
    </g>
  ),
  /* The double arrowhead of a sortable column, with no direction yet. */
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
