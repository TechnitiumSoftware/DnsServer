import { Fragment, useEffect, useMemo, useRef, useState } from 'react'
import { visibleSections, type Permission } from './sections'
import { aCamino, escribirRuta, leerRuta } from './ruta'
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
import { urlPublica } from './base'
import { PIE } from './pie'

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

/*
Un clic que el navegador debe atender él: botón central o derecho, o con
modificador —abrir en pestaña nueva, en ventana, descargar—. Interceptarlos
convertiría un enlace real en un botón disfrazado, que es justo lo que se acaba
de quitar.
*/
function clicSimple(e: React.MouseEvent): boolean {
  return e.button === 0 && !e.metaKey && !e.ctrlKey && !e.shiftKey && !e.altKey
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
  La sub efectiva. Una sección con sub-secciones SIEMPRE está en una de ellas,
  así que `null` quiere decir «la primera».

  Se resuelve aquí y no en cada rama —había cinco `sub ?? 'General'` sueltos, y
  el panel lateral repetía el mismo apaño para decidir a quién marcar— porque la
  regla repartida es justo la que se desincroniza: el menú decía «General» y la
  barra de direcciones ponía `/settings/`, que es media página.
  */
  const subActual = current?.subs != null ? (sub ?? current.subs[0] ?? null) : null

  /*
  La URL sigue al estado, y el estado sigue a la URL. El guardia está en
  `escribirRuta`, que no toca el historial si la ruta ya es la que está: sin él,
  responder a `popstate` fijando el estado volvería a escribir la ruta.
  */
  // La primera escritura normaliza la URL y no debe dejar entrada en el historial.
  const primerRender = useRef(true)

  const activaRef = useRef({ seccion: current?.id ?? 'about', sub })
  useEffect(() => {
    if (current == null) return
    activaRef.current = { seccion: current.id, sub: subActual }
    escribirRuta({ seccion: current.id, sub: subActual }, primerRender.current)
    primerRender.current = false
  }, [current, sub, subActual])

  useEffect(() => {
    function alCambiar() {
      const r = leerRuta(sections)
      if (r == null) {
        // Una ruta que no resuelve dejaba la barra y la pantalla diciendo cosas
        // distintas. La pantalla manda: se corrige la URL.
        escribirRuta({ seccion: activaRef.current.seccion, sub: activaRef.current.sub }, true)
        return
      }
      /*
      Una dirección a medias —`/settings/`, sin sub— se completa aquí y no en el
      efecto que escribe la ruta: al volver con «atrás» el estado no cambia
      (`sub` ya valía `null`), así que aquel efecto no se vuelve a ejecutar y la
      barra se quedaba diciendo media página.

      Y se completa reemplazando: empujar dejaría una entrada nueva que apunta a
      donde ya estamos, y el botón «atrás» daría vueltas sobre sí mismo.
      */
      const seccion = sections.find((x) => x.id === r.seccion)
      const suya = r.sub ?? seccion?.subs?.[0] ?? null
      if (suya !== r.sub) escribirRuta({ seccion: r.seccion, sub: suya }, true)

      setActive((v) => (v === r.seccion ? v : r.seccion))
      setSub((v) => (v === suya ? v : suya))
    }
    window.addEventListener('popstate', alCambiar)
    return () => window.removeEventListener('popstate', alCambiar)
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
          <img className={styles.mark} src={urlPublica('img/logo.png')} alt="" width={22} height={22} /> Technitium
        </div>
        <nav className={styles.slist} role="navigation" aria-label="Sections">
          {/*
          Esto es un menú de navegación, y hasta ahora decía ser un `tablist`.

          Se declaró como pestañas cuando la consola no tenía direcciones: doce
          `role="tab"` sobre un único panel. Al ganar rutas reales
          (`app/ruta.ts`) la descripción dejó de ser cierta —la guía de ARIA es
          explícita: si activar el elemento lleva a otra URL, es un enlace, no
          una pestaña—, y encima las sub-secciones colgaban DENTRO del
          `tablist` siendo botones sueltos, que es un hijo que ese rol no
          admite. Anunciaba «pestaña 3 de 12» y navegaba.

          Ahora son enlaces con `href` de verdad: se abren en pestaña nueva, se
          copian y se marcan. El clic normal lo intercepta la aplicación —no hay
          recarga—; el clic con modificador se deja pasar al navegador, que para
          eso las rutas existen como fichero. La sección activa se marca con
          `data-activa` (es estado visual) y `aria-current="page"` se reserva
          para UNA sola cosa: la página en la que se está, que es la
          sub-sección cuando la hay.
          */}
          {GRUPOS.map((grupo, g) => (
            <div className={styles.grupo} key={g}>
              {sections.filter((sec) => grupo.includes(sec.id)).map((sec) => {
                const activa = sec.id === current?.id
                const primera = sec.subs?.[0] ?? null
                return (
                  <div key={sec.id}>
                    <a
                      className={styles.s}
                      href={aCamino({ seccion: sec.id, sub: primera })}
                      data-activa={activa}
                      aria-current={activa && sec.subs == null ? 'page' : undefined}
                      onClick={(e) => {
                        if (!clicSimple(e)) return
                        e.preventDefault()
                        setActive(sec.id)
                        setSub(primera)
                        setCajon(false)
                      }}
                    >
                      <span className={styles.ico}>
                        <Icono nombre={ICONOS[sec.id] ?? 'about'} tam={16} />
                      </span>
                      {sec.label}
                    </a>
                    {/* main.js — los sub-items sólo se ven cuando su sección está
                        activa, igual que hoy las sub-pestañas. Sin desplegable. */}
                    {activa && sec.subs && (
                      <div className={styles.sub}>
                        {sec.subs.map((t) => (
                          <a
                            key={t}
                            className={styles.s2}
                            href={aCamino({ seccion: sec.id, sub: t })}
                            aria-current={activa && subActual === t ? 'page' : undefined}
                            onClick={(e) => {
                              if (!clicSimple(e)) return
                              e.preventDefault()
                              setSub(t)
                              setCajon(false)
                            }}
                          >
                            {t}
                          </a>
                        ))}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          ))}
        </nav>

        {/* El servidor y la cuenta, al pie. En estrecho se llega por el cajón. */}
        <div className={styles.pieLateral}>
          {/*
          Los enlaces del pie de upstream, recuperados.

          Upstream los tiene en un `div#footer` colgando del `body`, así que se
          ven en TODAS sus pantallas, incluida la de login: Technitium, Blog,
          Donate, DNS Client y GitHub. Aquí no había ninguno, y dos de ellos
          —technitium.com y dnsclient.net— no aparecían en ningún otro sitio de
          la consola: se habían perdido del todo.

          «About» no se repite porque en este rediseño es una sección del panel,
          justo encima.
          */}
          <div className={styles.pieEnlaces}>
            {PIE.map((e, i) => (
              <Fragment key={e.href}>
                {i > 0 && <span className={styles.sep}> | </span>}
                <a href={e.href} aria-label={e.nombre} target="_blank" rel="noreferrer">{e.texto}</a>
              </Fragment>
            ))}
          </div>
          {session.info && <span className={styles.host}>{session.info.dnsServerDomain}</span>}
          <div className={styles.menu}>
            <button
              className={styles.menuBtn}
              aria-haspopup="menu"
              aria-expanded={menuOpen}
              onClick={() => setMenuOpen((v) => !v)}
            >
              {displayName}
              <Icono nombre="chevronAbajo" tam={12} />
            </button>
            {menuOpen && (
              <div className={styles.menuList} role="menu">
                <button type="button" role="menuitem" onClick={() => abrir('profile')}>
                  My Profile
                </button>
                {/* main.js:71-78 — a un usuario de SSO se le ocultan estas dos. */}
                {!session.isSsoUser && (
                  <button type="button" role="menuitem" onClick={() => abrir('password')}>
                    Change Password
                  </button>
                )}
                {!session.isSsoUser && (
                  <button type="button" role="menuitem" onClick={() => abrir('twofa')}>
                    Configure 2FA
                  </button>
                )}
                <button type="button" role="menuitem" onClick={() => abrir('token')}>
                  Create API Token
                </button>
                <button type="button" role="menuitem" onClick={onLogout}>
                  Logout
                </button>
              </div>
            )}
          </div>
        </div>
      </aside>

      <div className={styles.main}>
        {/*
        En pantalla ANCHA no hay cabecero: sólo llevaba el dominio del servidor y
        el menú de cuenta, los dos pegados al borde derecho, y medía 1224×52 con
        el 78 % del ancho vacío —952 px de 1224— empujando el título de cada
        sección hasta `y=76`. Las dos cosas bajan al pie del panel lateral, que
        tenía 377 px libres, el 42 % de su alto.

        En pantalla ESTRECHA sí hace falta, porque el lateral es un cajón cerrado
        y su disparador tiene que vivir fuera.
        */}
        <header className={styles.rtop}>
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
            <img className={styles.mark} src={urlPublica('img/logo.png')} alt="" width={22} height={22} /> Technitium
          </span>
        </header>

        {/* Ni `tabpanel` ni `aria-labelledby`: desde que cada sección tiene su
            propia URL esto no es un panel que se alterna, es la página. */}
        <main className={styles.body} id="panel-seccion">
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
            sub={subActual ?? 'Leases'}
            onSubChange={setSub}
            canModify={permisos?.DhcpServer?.canModify !== false}
            canDelete={permisos?.DhcpServer?.canDelete !== false}
          />
        ) : current?.id === 'logs' ? (
          /* «Delete All Stats» vive en la pantalla de Logs pero pide permiso
             del Dashboard (WebServiceLogsApi.cs:135). No es un despiste. */
          <Logs
            token={session.token}
            sub={subActual ?? 'View Logs'}
            onSubChange={setSub}
            canDeleteLogs={permisos?.Logs?.canDelete !== false}
            canDeleteStats={permisos?.Dashboard?.canDelete !== false}
          />
        ) : current?.id === 'admin' ? (
          /* Sin props de permiso a propósito: upstream no oculta ni deshabilita
             nada dentro de Administration, sólo la sección entera (main.js:165). */
          <Admin token={session.token} sub={subActual ?? 'Sessions'} onSubChange={setSub} />
        ) : current?.id === 'settings' ? (
          /* main.js:906-930 — tres permisos distintos en una sola barra:
             guardar exige Settings.canModify, vaciar caché Cache.canDelete y
             copia/restauración Settings.canDelete. */
          <Settings
            token={session.token}
            sub={subActual ?? 'General'}
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
