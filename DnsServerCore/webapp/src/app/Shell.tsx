import { useEffect, useState } from 'react'
import { visibleSections, type Permission } from './sections'
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
  const sections = visibleSections(permisos)
  const [active, setActive] = useState(() => sections[0]?.id ?? 'about')
  const [menuOpen, setMenuOpen] = useState(false)
  const [cajon, setCajon] = useState(false)
  const [modal, setModal] = useState<ModalId | null>(null)
  const [sub, setSub] = useState<string | null>(null)
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
          <div role="tablist" aria-orientation="vertical">
            {GRUPOS.map((grupo, g) => (
              <div className={styles.grupo} key={g}>
            {sections.filter((sec) => grupo.includes(sec.id)).map((sec) => (
              <div key={sec.id}>
                <button
                  role="tab"
                  className={styles.s}
                  aria-selected={sec.id === current?.id}
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

        <main className={styles.body}>
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
        ) : (
          <div className={styles.placeholder}>
            <b>{current?.label}</b>
            Esta sección llega en la {current?.phase}.
          </div>
        )}
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
