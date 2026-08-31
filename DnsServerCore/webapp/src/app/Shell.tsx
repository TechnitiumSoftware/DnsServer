import { useEffect, useMemo, useRef, useState } from 'react'
import { visibleSections, type Permission } from './sections'
import { aCamino, escribirRuta, readRoute } from './ruta'
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
import { Icon, type IconName } from '../ui/Icono'
import { urlPublica } from './base'
import { Menu } from '../ui/Menu'
import { PieDeEnlaces } from '../ui/PieDeEnlaces'

type ModalId = 'profile' | 'password' | 'twofa' | 'token'

/** One glyph per section. No icon dependency: the server's CSP does not allow a
 *  CDN and an icon font would have to ship as a file in www/. */
/* The twelve section icons live in `ui/Icono`, drawn; here we only say which one
   each section carries. */
/*
The sidebar's three groups. It is not a new taxonomy: it is upstream's own order,
with a gap where the kind of task already changed. What you operate daily, what you
configure and what you consult.
*/
const GROUPS: string[][] = [
  ['dashboard', 'zones', 'cache', 'allowed', 'blocked', 'apps', 'dnsclient'],
  ['settings', 'dhcp', 'admin'],
  ['logs', 'about'],
]

const ICONS: Record<string, IconName> = {
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
A click the browser should handle itself: middle or right button, or with a
modifier —open in a new tab, in a window, download—. Intercepting them would turn a
real link into a button in disguise, which is exactly what has just been removed.
*/
function clicSimple(e: React.MouseEvent): boolean {
  return e.button === 0 && !e.metaKey && !e.ctrlKey && !e.shiftKey && !e.altKey
}

export function Shell({ session, onLogout }: { session: ShellSession; onLogout: () => void }) {
  const permissions = session.info?.permissions
  // Memoised: if it is recreated on every render, the `hashchange` resubscribes on each.
  const sections = useMemo(() => visibleSections(permissions), [permissions])
  /* The starting section comes from the address bar if it carries one, and only
     if not, from the first visible one. See `app/ruta.ts` for the reasoning. */
  const rutaInicial = readRoute(sections)
  const [active, setActive] = useState(() => rutaInicial?.section ?? sections[0]?.id ?? 'about')
  const [cajon, setCajon] = useState(false)
  const [modal, setModal] = useState<ModalId | null>(null)
  const [sub, setSub] = useState<string | null>(rutaInicial?.sub ?? null)
  const [displayName, setDisplayName] = useState(session.displayName)
  const [totpEnabled, setTotpEnabled] = useState(session.totpEnabled ?? false)

  function open(id: ModalId) {
    setModal(id)
  }

  // main.js — the document title carries the server domain and the version.
  useEffect(() => {
    if (session.info) {
      document.title = `${session.info.dnsServerDomain} - Technitium DNS Server v${session.info.version}`
    }
  }, [session.info])

  const current = sections.find((s) => s.id === active) ?? sections[0]

  /*
  The effective sub. A section with sub-sections is ALWAYS in one of them, so
  `null` means "the first one".

  It is resolved here and not in each branch —there were five loose
  `sub ?? 'General'`, and the sidebar repeated the same workaround to decide what
  to mark— because a rule spread around is precisely the one that goes out of
  sync: the menu said "General" and the address bar said `/settings/`, which is
  half a page.
  */
  const subActual = current?.subs != null ? (sub ?? current.subs[0] ?? null) : null

  /*
  The URL follows the state, and the state follows the URL. The guard is in
  `escribirRuta`, which does not touch history if the route is already the current
  one: without it, responding to `popstate` by setting the state would write the
  route again.
  */
  // La primera escritura normaliza la URL y no debe dejar entrada en el historial.
  const primerRender = useRef(true)

  const activaRef = useRef({ section: current?.id ?? 'about', sub })
  useEffect(() => {
    if (current == null) return
    activaRef.current = { section: current.id, sub: subActual }
    escribirRuta({ section: current.id, sub: subActual }, primerRender.current)
    primerRender.current = false
  }, [current, sub, subActual])

  useEffect(() => {
    function alCambiar() {
      const r = readRoute(sections)
      if (r == null) {
        // A route that does not resolve left the bar and the screen saying different
        // distintas. La pantalla manda: se corrige la URL.
        escribirRuta({ section: activaRef.current.section, sub: activaRef.current.sub }, true)
        return
      }
      /*
      A half address —`/settings/`, with no sub— is completed here and not in the
      effect that writes the route: on going "back" the state does not change
      (`sub` was already `null`), so that effect does not run again and the bar was
      left saying half a page.

      And it is completed by replacing: pushing would leave a new entry pointing at
      where we already are, and the back button would go round in circles.
      */
      const section = sections.find((x) => x.id === r.section)
      const suya = r.sub ?? section?.subs?.[0] ?? null
      if (suya !== r.sub) escribirRuta({ section: r.section, sub: suya }, true)

      setActive((v) => (v === r.section ? v : r.section))
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

      <aside className={styles.side} data-open={cajon}>
        <div className={styles.sbrand}>
          <img className={styles.mark} src={urlPublica('img/logo.png')} alt="" width={22} height={22} /> Technitium
        </div>
        <nav className={styles.slist} role="navigation" aria-label="Sections">
          {/*
          This is a navigation menu, and until now it claimed to be a `tablist`.

          It was declared as tabs when the console had no addresses: twelve
          `role="tab"` over a single panel. Once it gained real routes
          (`app/ruta.ts`) the description stopped being true —the ARIA guidance is
          explicit: if activating the element leads to another URL, it is a link,
          not a tab— and on top of that the sub-sections hung INSIDE the `tablist`
          as loose buttons, which is a child that role does not allow. It announced
          "tab 3 of 12" and navigated.

          Now they are links with real `href`s: they open in a new tab, they are
          copied and bookmarked. The plain click is intercepted by the application
          —there is no reload—; the modifier click is passed through to the
          browser, which is what the routes existing as files is for. The active
          section is marked with `data-activa` (that is visual state) and
          `aria-current="page"` is reserved for ONE thing: the page you are on,
          which is the sub-section when there is one.
          */}
          {GROUPS.map((group, g) => (
            <div className={styles.group} key={g}>
              {sections.filter((sec) => group.includes(sec.id)).map((sec) => {
                const active = sec.id === current?.id
                const primera = sec.subs?.[0] ?? null
                return (
                  <div key={sec.id}>
                    <a
                      className={styles.s}
                      href={aCamino({ section: sec.id, sub: primera })}
                      data-active={active}
                      aria-current={active && sec.subs == null ? 'page' : undefined}
                      onClick={(e) => {
                        if (!clicSimple(e)) return
                        e.preventDefault()
                        setActive(sec.id)
                        setSub(primera)
                        setCajon(false)
                      }}
                    >
                      <span className={styles.ico}>
                        <Icon name={ICONS[sec.id] ?? 'about'} tam={16} />
                      </span>
                      {sec.label}
                    </a>
                    {/* main.js — the sub-items are only visible when their section is
                        active, exactly as the sub-tabs are today. No dropdown. */}
                    {active && sec.subs && (
                      <div className={styles.sub}>
                        {sec.subs.map((t) => (
                          <a
                            key={t}
                            className={styles.s2}
                            href={aCamino({ section: sec.id, sub: t })}
                            aria-current={active && subActual === t ? 'page' : undefined}
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

        {/* The server and the account, at the foot. When narrow you reach it via the drawer. */}
        <div className={styles.pieLateral}>
          {/*
          Upstream's footer links, recovered.

          Upstream has them in a `div#footer` hanging off the `body`, so they are
          visible on ALL its screens, the login one included: Technitium, Blog,
          Donate, DNS Client and GitHub. There were none here, and two of them
          —technitium.com and dnsclient.net— appeared nowhere else in the console:
          they had been lost entirely.

          "About" is not repeated because in this redesign it is a sidebar section,
          right above.
          */}
          <PieDeEnlaces className={styles.pieEnlaces} />
          {session.info && <span className={styles.host}>{session.info.dnsServerDomain}</span>}
          <Menu etiqueta={displayName} rotulo={displayName} ancla="izquierda" comoFila>
            {(close) => (
              <>
                <button type="button" onClick={() => { close(); open('profile') }}>
                  My Profile
                </button>
                {/* main.js:71-78 — a un usuario de SSO se le ocultan estas dos. */}
                {!session.isSsoUser && (
                  <button type="button" onClick={() => { close(); open('password') }}>
                    Change Password
                  </button>
                )}
                {!session.isSsoUser && (
                  <button type="button" onClick={() => { close(); open('twofa') }}>
                    Configure 2FA
                  </button>
                )}
                <button type="button" onClick={() => { close(); open('token') }}>
                  Create API Token
                </button>
                <button type="button" onClick={() => { close(); onLogout() }}>
                  Logout
                </button>
              </>
            )}
          </Menu>
        </div>
      </aside>

      <div className={styles.main}>
        {/*
        On a WIDE screen there is no header: it only carried the server domain and
        the account menu, both pinned to the right edge, and it measured 1224×52
        with 78 % of the width empty —952 px out of 1224— pushing every section's
        title down to `y=76`. Both things move down to the foot of the sidebar,
        which had 377 px free, 42 % of its height.

        On a NARROW screen it is needed, because the sidebar is a closed drawer and
        its trigger has to live outside.
        */}
        <header className={styles.rtop}>
          <button
            type="button"
            className={styles.hamburguesa}
            aria-label="Menu"
            aria-expanded={cajon}
            onClick={() => setCajon((v) => !v)}
          >
            <Icon name="menu" tam={18} />
          </button>
          <span className={styles.marcaTop}>
            <img className={styles.mark} src={urlPublica('img/logo.png')} alt="" width={22} height={22} /> Technitium
          </span>
        </header>

        {/* Neither `tabpanel` nor `aria-labelledby`: ever since each section has its
            own URL this is not a panel being switched, it is the page. */}
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
            canModify={permissions?.Zones?.canModify !== false}
            canDelete={permissions?.Zones?.canDelete !== false}
          />
        ) : current?.id === 'dhcp' ? (
          <Dhcp
            token={session.token}
            sub={subActual ?? 'Leases'}
            onSubChange={setSub}
            canModify={permissions?.DhcpServer?.canModify !== false}
            canDelete={permissions?.DhcpServer?.canDelete !== false}
          />
        ) : current?.id === 'logs' ? (
          /* "Delete All Stats" lives on the Logs screen but asks for the
             Dashboard's permission (WebServiceLogsApi.cs:135). Not an oversight. */
          <Logs
            token={session.token}
            sub={subActual ?? 'View Logs'}
            onSubChange={setSub}
            canDeleteLogs={permissions?.Logs?.canDelete !== false}
            canDeleteStats={permissions?.Dashboard?.canDelete !== false}
          />
        ) : current?.id === 'admin' ? (
          /* No permission props on purpose: upstream hides and disables nothing
             inside Administration, only the whole section (main.js:165). */
          <Admin token={session.token} sub={subActual ?? 'Sessions'} onSubChange={setSub} />
        ) : current?.id === 'settings' ? (
          /* main.js:906-930 — three different permissions in a single bar:
             saving requires Settings.canModify, flushing the cache
             Cache.canDelete, and backup/restore Settings.canDelete. */
          <Settings
            token={session.token}
            sub={subActual ?? 'General'}
            onSubChange={setSub}
            canModify={permissions?.Settings?.canModify !== false}
            canFlushCache={permissions?.Cache?.canDelete !== false}
            canBackup={permissions?.Settings?.canDelete !== false}
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
