import { useEffect, useState } from 'react'
import { useTheme, THEMES } from '../theme/ThemeProvider'
import { visibleSections, type Permission } from './sections'
import styles from './Shell.module.css'

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
  const { theme, setTheme } = useTheme()

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
              {session.displayName} ▾
            </button>
            {menuOpen && (
              <div className={styles.menuList}>
                <button type="button">My Profile</button>
                {/* main.js:71-78 — a un usuario de SSO se le ocultan estas dos. */}
                {!session.isSsoUser && <button type="button">Change Password</button>}
                {!session.isSsoUser && <button type="button">Configure 2FA</button>}
                <button type="button">Create API Token</button>
                <button
                  type="button"
                  onClick={() => {
                    const next = THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length]
                    setTheme(next)
                  }}
                >
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
    </div>
  )
}
