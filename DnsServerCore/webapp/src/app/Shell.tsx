import { useEffect, useMemo, useRef, useState } from 'react'
import { visibleSections, type Permission } from './sections'
import { escribirRuta, leerRuta } from './ruta'
import { ChangePassword } from '../screens/modals/ChangePassword'
import { Configure2FA } from '../screens/modals/Configure2FA'
import { CreateApiToken } from '../screens/modals/CreateApiToken'
import { MyProfile } from '../screens/modals/MyProfile'
import { Dashboard } from '../screens/dashboard/Dashboard'
import { DnsClient } from '../screens/dnsclient/DnsClient'
import { About } from '../screens/about/About'
import { Apps } from '../screens/apps/Apps'
import { Cache, Allowed, Blocked } from '../screens/listas/Listas'
import { Settings } from '../screens/settings/Settings'
import { Zones } from '../screens/zones/Zones'
import { Dhcp } from '../screens/dhcp/Dhcp'
import { Logs } from '../screens/logs/Logs'
import { Admin } from '../screens/admin/Admin'
import styles from './Shell.module.css'
import { Icono, type NombreIcono } from '../ui/Icono'

type ModalId = 'profile' | 'password' | 'twofa' | 'token'

/** Un glifo por sección. Sin dependencia de iconos: la CSP del servidor no
 *  permite CDN y una fuente de iconos tendría que ir como fichero en www/. */
/* Los doce iconos de sección viven en `ui/Icono`, dibujados; aquí sólo se dice
   cuál lleva cada una. */
/*
Los tres grupos del panel. No es una taxonomía nueva: es el mismo orden de
upstream, con hueco donde ya cambiaba el tipo de tarea. Lo que se opera a
diario, lo que se configura y lo que se consulta.
*/
const GRUPOS: string[][] = [
  ['dashboard', 'zones', 'cache', 'allowed', 'blocked', 'apps', 'dnsclient'],
  ['settings', 'dhcp', 'admin'],
  ['logs', 'about'],
]

const ICONOS: Record<string, NombreIcono> = {
  dashboard: 'dashboard', zones: 'zones', cache: 'cache', allowed: 'allowed',
  blocked: 'blocked', apps: 'apps', dnsclient: 'dnsclient', settings: 'settings',
  dhcp: 'dhcp', admin: 'admin', logs: 'logs', about: 'about',
}

export interface ShellSession {
  token: string
  displayName: string
  username: string
  isSsoUser?: boolean
  totpEnabled?: boolean
  info?: {
    version: string
    uptimestamp: string
    dnsServerDomain: string
    permissions?: Record<string, Permission>
  }
}

export function Shell({ session, onLogout }: { session: ShellSession; onLogout: () => void }) {
  const permisos = session.info?.permissions
  // Memorizada: si se recrea en cada render, el `hashchange` se resuscribe en cada uno.
  const sections = useMemo(() => visibleSections(permisos), [permisos])
  /* La sección de arranque sale de la barra de direcciones si la trae, y sólo
     si no, de la primera visible. Ver `app/ruta.ts` para por qué va en el hash. */
  const rutaInicial = leerRuta(sections)
  const [active, setActive] = useState(() => rutaInicial?.seccion ?? sections[0]?.id ?? 'about')
  const [menuOpen, setMenuOpen] = useState(false)
  const [cajon, setCajon] = useState(false)
  const [modal, setModal] = useState<ModalId | null>(null)
  const [sub, setSub] = useState<string | null>(rutaInicial?.sub ?? null)
  const [displayName, setDisplayName] = useState(session.displayName)
  const [totpEnabled, setTotpEnabled] = useState(session.totpEnabled ?? false)

  function abrir(id: ModalId) {
    setMenuOpen(false)
    setModal(id)
  }

  // main.js — el título del documento lleva el dominio del servidor y la versión.
  useEffect(() => {
    if (session.info) {
      document.title = `${session.info.dnsServerDomain} - Technitium DNS Server v${session.info.version}`
    }
  }, [session.info])

  const current = sections.find((s) => s.id === active) ?? sections[0]

  /*
  La URL sigue al estado, y el estado sigue a la URL. El guardia del `hashchange`
  es lo que evita el bucle: sin él, escribir el hash dispara el evento, que
  vuelve a fijar el estado, que vuelve a escribir el hash.
  */
  /*
  Las flechas del patrón de pestañas. Vertical, así que Arriba y Abajo; y `Home`
  y `End` a los extremos, que es lo que la guía de ARIA da por supuesto. Mueven
  el foco Y activan, como hace un `tablist` de selección automática: aquí cambiar
  de sección no cuesta nada y obligar a pulsar Enter después sería un paso de más.
  */
  const pestanas = useRef<Record<string, HTMLButtonElement | null>>({})
  const focoPendiente = useRef<string | null>(null)

  function porTeclado(e: React.KeyboardEvent) {
    const teclas = ['ArrowDown', 'ArrowUp', 'Home', 'End']
    if (!teclas.includes(e.key)) return
    const i = sections.findIndex((s) => s.id === current?.id)
    if (i < 0) return
    const destino =
      e.key === 'Home' ? 0
      : e.key === 'End' ? sections.length - 1
      : (i + (e.key === 'ArrowDown' ? 1 : -1) + sections.length) % sections.length
    const id = sections[destino]?.id
    if (id == null) return
    e.preventDefault()
    setActive(id)
    setSub(null)
    focoPendiente.current = id
  }

  /*
  El foco se mueve DESPUÉS del commit, no en un `requestAnimationFrame`. Con el
  cuadro suelto el salto Dashboard → Zones perdía el foco —y sólo ése—: al
  desmontar las gráficas del Dashboard, el botón al que se apuntaba todavía no
  existía y el foco se caía al `body`. Medido: los otros once saltos lo
  conservaban, así que era una carrera y no un descuido.
  */
  useEffect(() => {
    const id = focoPendiente.current
    if (id == null) return
    focoPendiente.current = null
    pestanas.current[id]?.focus()
  })

  const activaRef = useRef({ seccion: current?.id ?? 'about', sub })
  useEffect(() => {
    if (current == null) return
    activaRef.current = { seccion: current.id, sub }
    escribirRuta({ seccion: current.id, sub }, window.location.hash === '')
  }, [current, sub])

  useEffect(() => {
    function alCambiar() {
      const r = leerRuta(sections)
      if (r == null) {
        // Un `#/loquesea` que no resuelve dejaba la barra y la pantalla diciendo
        // cosas distintas. La pantalla manda: se corrige la URL.
        escribirRuta({ seccion: activaRef.current.seccion, sub: activaRef.current.sub }, true)
        return
      }
      setActive((v) => (v === r.seccion ? v : r.seccion))
      setSub((v) => (v === r.sub ? v : r.sub))
    }
    window.addEventListener('hashchange', alCambiar)
    return () => window.removeEventListener('hashchange', alCambiar)
  }, [sections])

  return (
    <div className={styles.shell}>
      {cajon && (
        <button
          type="button"
          className={styles.velo}
          aria-label="Close menu"
          onClick={() => setCajon(false)}
        />
      )}

      <aside className={styles.side} data-abierto={cajon}>
        <div className={styles.sbrand}>
          <span className={styles.mark}>T</span> Technitium
        </div>
        <nav className={styles.slist} role="navigation" aria-label="Sections">
          {/*
          El patrón de pestañas se declaraba y no se cumplía: doce `role="tab"`
          sin un solo `role="tabpanel"`, sin `aria-controls` y con las doce en el
          orden de tabulación. Un lector de pantalla anunciaba «pestaña 1 de 12»
          y prometía flechas que no hacían nada; y para llegar a «About» con el
          teclado había que pulsar Tab once veces. Upstream sí lo cumple —28
          `role="tabpanel"` y `aria-controls` en todas—, así que esto era una
          pérdida nuestra, no una diferencia de estilo.
          */}
          <div role="tablist" aria-orientation="vertical" onKeyDown={porTeclado}>
            {GRUPOS.map((grupo, g) => (
              <div className={styles.grupo} key={g} role="presentation">
            {sections.filter((sec) => grupo.includes(sec.id)).map((sec) => (
              <div key={sec.id} role="presentation">
                <button
                  role="tab"
                  id={`tab-${sec.id}`}
                  aria-controls="panel-seccion"
                  className={styles.s}
                  aria-selected={sec.id === current?.id}
                  tabIndex={sec.id === current?.id ? 0 : -1}
                  ref={(el) => { pestanas.current[sec.id] = el }}
                  onClick={() => { setActive(sec.id); setSub(null); setCajon(false) }}
                >
                  <span className={styles.ico}>
                    <Icono nombre={ICONOS[sec.id] ?? 'about'} tam={16} />
                  </span>
                  {sec.label}
                </button>
                {/* main.js — los sub-items sólo se ven cuando su sección está
                    activa, igual que hoy las sub-pestañas. Sin desplegable. */}
                {sec.id === current?.id && sec.subs && (
                  <div className={styles.sub}>
                    {sec.subs.map((t, i) => (
                      <button
                        key={t}
                        className={styles.s2}
                        aria-current={(sub ?? sec.subs![0]) === t || (sub === null && i === 0)}
                        onClick={() => { setSub(t); setCajon(false) }}
                      >
                        {t}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            ))}
              </div>
            ))}
          </div>
        </nav>
      </aside>

      <div className={styles.main}>
        <header className={styles.rtop}>
          {/* En pantalla estrecha el lateral es un cajón, así que el cabecero
              tiene que traer su disparador y la marca. */}
          <button
            type="button"
            className={styles.hamburguesa}
            aria-label="Menu"
            aria-expanded={cajon}
            onClick={() => setCajon((v) => !v)}
          >
            <Icono nombre="menu" tam={18} />
          </button>
          <span className={styles.marcaTop}>
            <span className={styles.mark}>T</span> Technitium
          </span>
          {session.info && <span className={styles.host}>{session.info.dnsServerDomain}</span>}
          <div className={styles.menu}>
            <button className={styles.menuBtn} onClick={() => setMenuOpen((v) => !v)}>
              {displayName}
              <Icono nombre="chevronAbajo" tam={12} />
            </button>
            {menuOpen && (
              <div className={styles.menuList}>
                <button type="button" onClick={() => abrir('profile')}>
                  My Profile
                </button>
                {/* main.js:71-78 — a un usuario de SSO se le ocultan estas dos. */}
                {!session.isSsoUser && (
                  <button type="button" onClick={() => abrir('password')}>
                    Change Password
                  </button>
                )}
                {!session.isSsoUser && (
                  <button type="button" onClick={() => abrir('twofa')}>
                    Configure 2FA
                  </button>
                )}
                <button type="button" onClick={() => abrir('token')}>
                  Create API Token
                </button>
                <button type="button" onClick={onLogout}>
                  Logout
                </button>
              </div>
            )}
          </div>
        </header>

        <main
          className={styles.body}
          id="panel-seccion"
          role="tabpanel"
          aria-labelledby={current ? `tab-${current.id}` : undefined}
        >
        {current?.id === 'dashboard' ? (
          <Dashboard token={session.token} />
        ) : current?.id === 'dnsclient' ? (
          <DnsClient token={session.token} />
        ) : current?.id === 'about' ? (
          <About token={session.token} info={session.info} />
        ) : current?.id === 'apps' ? (
          <Apps token={session.token} />
        ) : current?.id === 'cache' ? (
          <Cache token={session.token} />
        ) : current?.id === 'allowed' ? (
          <Allowed token={session.token} />
        ) : current?.id === 'blocked' ? (
          <Blocked token={session.token} />
        ) : current?.id === 'zones' ? (
          <Zones
            token={session.token}
            canModify={permisos?.Zones?.canModify !== false}
            canDelete={permisos?.Zones?.canDelete !== false}
          />
        ) : current?.id === 'dhcp' ? (
          <Dhcp
            token={session.token}
            sub={sub ?? 'Leases'}
            onSubChange={setSub}
            canModify={permisos?.DhcpServer?.canModify !== false}
            canDelete={permisos?.DhcpServer?.canDelete !== false}
          />
        ) : current?.id === 'logs' ? (
          /* «Delete All Stats» vive en la pantalla de Logs pero pide permiso
             del Dashboard (WebServiceLogsApi.cs:135). No es un despiste. */
          <Logs
            token={session.token}
            sub={sub ?? 'View Logs'}
            onSubChange={setSub}
            canDeleteLogs={permisos?.Logs?.canDelete !== false}
            canDeleteStats={permisos?.Dashboard?.canDelete !== false}
          />
        ) : current?.id === 'admin' ? (
          /* Sin props de permiso a propósito: upstream no oculta ni deshabilita
             nada dentro de Administration, sólo la sección entera (main.js:165). */
          <Admin token={session.token} sub={sub ?? 'Sessions'} onSubChange={setSub} />
        ) : current?.id === 'settings' ? (
          /* main.js:906-930 — tres permisos distintos en una sola barra:
             guardar exige Settings.canModify, vaciar caché Cache.canDelete y
             copia/restauración Settings.canDelete. */
          <Settings
            token={session.token}
            sub={sub ?? 'General'}
            onSubChange={setSub}
            canModify={permisos?.Settings?.canModify !== false}
            canFlushCache={permisos?.Cache?.canDelete !== false}
            canBackup={permisos?.Settings?.canDelete !== false}
          />
        ) : null}
        </main>
      </div>

      <MyProfile
        open={modal === 'profile'}
        onOpenChange={(o) => setModal(o ? 'profile' : null)}
        token={session.token}
        onSaved={setDisplayName}
      />
      <ChangePassword
        open={modal === 'password'}
        onOpenChange={(o) => setModal(o ? 'password' : null)}
        totpEnabled={totpEnabled}
        token={session.token}
      />
      <Configure2FA
        open={modal === 'twofa'}
        onOpenChange={(o) => setModal(o ? 'twofa' : null)}
        token={session.token}
        onChanged={setTotpEnabled}
      />
      <CreateApiToken
        open={modal === 'token'}
        onOpenChange={(o) => setModal(o ? 'token' : null)}
        username={session.username}
        token={session.token}
      />
    </div>
  )
}
