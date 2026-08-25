import { useEffect, useState } from 'react'
import { visibleSections, type Permission } from './sections'
import { ChangePassword } from '../screens/modals/ChangePassword'
import { ChangeTheme } from '../screens/modals/ChangeTheme'
import { Configure2FA } from '../screens/modals/Configure2FA'
import { CreateApiToken } from '../screens/modals/CreateApiToken'
import { MyProfile } from '../screens/modals/MyProfile'
import styles from './Shell.module.css'

type ModalId = 'profile' | 'password' | 'twofa' | 'token' | 'theme'

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
      <header className={styles.top}>
        <div className={styles.brand}>
          <span className={styles.mark}>T</span> Technitium
        </div>
        <div className={styles.right}>
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
                <button type="button" onClick={() => abrir('theme')}>
                  Change Theme
                </button>
                <button type="button" onClick={onLogout}>
                  Logout
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      <nav className={styles.nav} role="navigation" aria-label="Sections">
        <div role="tablist">
          {sections.map((s) => (
            <button
              key={s.id}
              role="tab"
              className={styles.tab}
              aria-selected={s.id === current?.id}
              onClick={() => setActive(s.id)}
            >
              {s.label}
            </button>
          ))}
        </div>
      </nav>

      <main className={styles.body}>
        <div className={styles.placeholder}>
          <b>{current?.label}</b>
          Esta sección llega en la {current?.phase}.
        </div>
      </main>

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
      <ChangeTheme open={modal === 'theme'} onOpenChange={(o) => setModal(o ? 'theme' : null)} />
    </div>
  )
}
