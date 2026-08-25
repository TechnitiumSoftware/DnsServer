import { useEffect, useState } from 'react'
import { visibleSections, type Permission } from './sections'
import { ChangePassword } from '../screens/modals/ChangePassword'
import { Configure2FA } from '../screens/modals/Configure2FA'
import { CreateApiToken } from '../screens/modals/CreateApiToken'
import { MyProfile } from '../screens/modals/MyProfile'
import { Dashboard } from '../screens/dashboard/Dashboard'
import styles from './Shell.module.css'

type ModalId = 'profile' | 'password' | 'twofa' | 'token'

/** Un glifo por sección. Sin dependencia de iconos: la CSP del servidor no
 *  permite CDN y una fuente de iconos tendría que ir como fichero en www/. */
const ICONOS: Record<string, string> = {
  dashboard: '▣', zones: '◆', cache: '○', allowed: '✓', blocked: '⊘', apps: '⊞',
  dnsclient: '⌕', settings: '⚙', dhcp: '▤', admin: '☺', logs: '≡', about: 'ⓘ',
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
  const sections = visibleSections(session.info?.permissions)
  const [active, setActive] = useState(() => sections[0]?.id ?? 'about')
  const [menuOpen, setMenuOpen] = useState(false)
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
      <aside className={styles.side}>
        <div className={styles.sbrand}>
          <span className={styles.mark}>T</span> Technitium
        </div>
        <nav className={styles.slist} role="navigation" aria-label="Sections">
          <div role="tablist" aria-orientation="vertical">
            {sections.map((sec) => (
              <div key={sec.id}>
                <button
                  role="tab"
                  className={styles.s}
                  aria-selected={sec.id === current?.id}
                  onClick={() => { setActive(sec.id); setSub(null) }}
                >
                  <span className={styles.ico} aria-hidden="true">{ICONOS[sec.id] ?? '•'}</span>
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
                        onClick={() => setSub(t)}
                      >
                        {t}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </nav>
      </aside>

      <div className={styles.main}>
        <header className={styles.rtop}>
          {session.info && <span className={styles.host}>{session.info.dnsServerDomain}</span>}
          <div className={styles.menu}>
            <button className={styles.menuBtn} onClick={() => setMenuOpen((v) => !v)}>
              {displayName} ▾
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
