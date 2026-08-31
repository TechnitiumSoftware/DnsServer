import { useEffect, useState, type ReactNode } from 'react'
import { checkForUpdate } from '../../api/user'
import { Alert } from '../../ui/Alert'
import { Button } from '../../ui/Button'
import { SectionHeader } from '../../ui/SectionHeader'
import { Empty } from '../../ui/Empty'
import { desdeAhora, fechaHora } from '../../lib/fechas'
import styles from './About.module.css'
import { Cuerpo, Panel } from '../../ui/Panel'
import { urlPublica } from '../../app/base'

interface Info { version: string; uptimestamp: string; dnsServerDomain: string }

/* Los dos destinos que se repiten, para que el texto y el título no se separen. */
const API_DOCS = 'https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md'
const DONAR = 'https://go.technitium.com/?id=35'

/** Enlace externo: siempre en pestaña nueva y sin ceder el `opener`. */
function Enlace({
  href,
  clase,
  children,
}: {
  href: string
  clase?: string
  children: ReactNode
}) {
  return (
    <a className={clase} href={href} target="_blank" rel="noreferrer">
      {children}
    </a>
  )
}

export function About({ token, info }: { token: string | null; info?: Info }) {
  /*
  «sin-mirar» es un estado REAL —el servidor dice que tiene los avisos de
  actualización apagados— y por eso no vale para contar un fallo: con la
  llamada caída la pantalla decía «Update notifications are turned off for this
  server.», que es una afirmación sobre la configuración del servidor y no sobre
  lo que acaba de pasar. De ahí el quinto estado.
  */
  const [update, setUpdate] = useState<'sin-mirar' | 'mirando' | 'al-dia' | 'hay' | 'fallo'>(
    'sin-mirar',
  )

  useEffect(() => {
    void (async () => {
      const r = await checkForUpdate(token)
      if (r.kind === 'skipped') return
      if (r.kind === 'ok') {
        const d = r.data as { response?: { updateAvailable?: boolean } }
        setUpdate(d.response?.updateAvailable ? 'hay' : 'al-dia')
        return
      }
      setUpdate('fallo')
    })()
  }, [token])

  async function mirar() {
    setUpdate('mirando')
    const r = await checkForUpdate(token, true)
    if (r.kind === 'ok') {
      const d = r.data as { response?: { updateAvailable?: boolean } }
      setUpdate(d.response?.updateAvailable ? 'hay' : 'al-dia')
    } else setUpdate(r.kind === 'skipped' ? 'sin-mirar' : 'fallo')
  }

  return (
    <>
      <SectionHeader titulo="About" />
    <div className={styles.grid}>
      <Panel className={styles.panel}>
        <Cuerpo>
          <div className={styles.head}>
            {/* El logo de Technitium, no una inicial nuestra. Upstream lo pone
                justo aquí (`index.html:3483`) y el fichero viaja en `public/img/`
                desde el andamiaje: lo teníamos y no lo usábamos. */}
            <img className={styles.mark} src={urlPublica('img/logo.png')} alt="" width={38} height={38} />
            <div>
              <h2 className={styles.h1}>Technitium DNS Server</h2>
              <div className={styles.ver}>Version {info?.version ?? '—'}</div>
            </div>
          </div>
          {/*
          El texto y los enlaces son los de upstream, literales.

          Esta pantalla se había quedado con la prosa y sin los destinos: de los
          nueve enlaces del panel original sobrevivía uno (GitHub). Faltaban
          enteras «Help Topics», «Support» y «Donate», y en las que quedaban el
          texto seguía diciendo «read the change log» sin que «change log»
          llevara a ninguna parte.

          No es un detalle de estilo. Un fork que borra del panel del autor su
          enlace de donaciones, su correo de soporte y su documentación está
          quitando funcionalidad al producto ajeno que dice sólo repintar; es de
          la misma familia que sustituir su logo por una inicial propia.
          */}
          <div className={styles.prose}>
            <p>Copyright (C) 2026 Shreyas Zare (shreyas@technitium.com)</p>
            <p>
              This program comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
              welcome to redistribute it under certain conditions.
            </p>
            <p>
              Source code available under{' '}
              <Enlace href="https://go.technitium.com/?id=24">GNU General Public License v3.0</Enlace>{' '}
              on <Enlace href="https://github.com/TechnitiumSoftware/DnsServer">GitHub</Enlace>
            </p>

            <h4><Enlace href="https://go.technitium.com/?id=23">What&apos;s New?</Enlace></h4>
            <p>
              Read the <Enlace href="https://go.technitium.com/?id=23">change log</Enlace> to know
              what&apos;s new in this release.
            </p>

            <h4><Enlace href={API_DOCS}>API Documentation</Enlace></h4>
            <p>
              The DNS Server HTTP API allows any 3rd party app or script to configure the DNS Server.
              The HTTP API is used by this web console and thus all the actions that this web console
              does can be performed via the API. Read the{' '}
              <Enlace href={API_DOCS}>HTTP API documentation</Enlace> for complete details.
            </p>

            <h4><Enlace href="https://go.technitium.com/?id=25">Help Topics</Enlace></h4>
            <p>
              Read the latest{' '}
              <Enlace href="https://go.technitium.com/?id=25">online help topics</Enlace> which
              contains the DNS Server user manual and covers frequently asked questions.
            </p>

            <h4>Support</h4>
            <p>
              For support, send an email to{' '}
              <Enlace href="mailto:support@technitium.com">support@technitium.com</Enlace>.
            </p>
            <p>
              Follow{' '}
              <Enlace href="https://mastodon.social/@technitium">@technitium@mastodon.social</Enlace>{' '}
              on Mastodon.
              <br />
              Checkout <Enlace href="https://blog.technitium.com/">Technitium Blog</Enlace>.
            </p>
            <p>
              Join <Enlace href="https://www.reddit.com/r/technitium/">/r/technitium</Enlace> on Reddit.
            </p>

            <h4><Enlace href={DONAR}>Donate</Enlace></h4>
            <p>
              Make a contribution to Technitium and help making new software, updates, and features
              possible.
            </p>
            <p>
              <Enlace href={DONAR} clase={styles.destino}>Donate Now!</Enlace>
            </p>
          </div>
        </Cuerpo>
      </Panel>

      <div className={styles.col}>
        <Panel titulo="Server" className={styles.panel}>
          <Cuerpo>
            <dl className={styles.kv}>
              <dt>Version</dt><dd>{info?.version ?? '—'}</dd>
              <dt>Domain</dt><dd>{info?.dnsServerDomain ?? '—'}</dd>
              <dt>Up since</dt><dd>{info ? fechaHora(info.uptimestamp) : '—'}</dd>
              <dt>Uptime</dt><dd>{info ? desdeAhora(info.uptimestamp) : '—'}</dd>
            </dl>
          </Cuerpo>
        </Panel>
        <Panel titulo="Update" className={styles.panel}>
          <Cuerpo>
            {update === 'al-dia' && <Alert type="info" title="Note:">No update available. You are running the latest version.</Alert>}
            {/*
            main.js:751-767 — el título por defecto es «New Update Available!» y
            el MENSAJE lo manda el servidor; si no viene, upstream no enseña
            ninguno. La frase que había aquí estaba inventada, y en castellano.
            */}
            {update === 'hay' && <Alert type="success" title="New Update Available!" />}
            {update === 'sin-mirar' && <Empty compacto>Update notifications are turned off for this server.</Empty>}
            {update === 'fallo' && (
              <Alert type="danger" title="Error!">Unable to check for updates.</Alert>
            )}
            <div className={styles.accion}>
              <Button disabled={update === 'mirando'} onClick={() => void mirar()}>Check for Update</Button>
            </div>
          </Cuerpo>
        </Panel>
      </div>
    </div>
    </>
  )
}
