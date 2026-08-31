import { useCallback, useEffect, useId, useState } from 'react'
import { Alert } from '../../ui/Alert'
import { Panel } from '../../ui/Panel'
import { Button } from '../../ui/Button'
import { Input, Select } from '../../ui/Field'
import { SectionHeader } from '../../ui/SectionHeader'
import { Loading } from '../../ui/Empty'
import { getSsoConfig, setSsoConfig, type SsoConfig } from '../../api/admin'
import { serializarTabla, type Celda } from './tabla'
import {
  avisoDeFallo,
  Check,
  Confirmar,
  adminStyles as styles,
  type Aviso,
} from './partes'
import frm from '../../ui/Form.module.css'
import { TablaEditable } from '../../ui/TablaEditable'

/*
`refreshAdminSsoConfig`, `loadAdminSsoConfig` y `saveAdminSsoConfig`
(auth.js:2152-2313). Es la pantalla que CONFIGURA el SSO; el inicio de sesión
por SSO ya está resuelto en la fase 2 y no se toca aquí.

Cuatro cosas del servidor que gobiernan este formulario:

  1. **`admin/sso/set` NO devuelve `localGroups`** (WebServiceAuthApi.cs:1790
     llama a `WriteSsoConfig` con `includeGroups: false`). Upstream sobrevive
     porque los guardó en una variable global al hacer el `get`; aquí se
     conservan igual, en estado, y el guardado sólo refresca el resto.
  2. **El secreto llega enmascarado como `"************"`** y el servidor
     IGNORA ese valor exacto al guardar (líneas 339-342 y 1738). Por eso el
     campo se rellena con la máscara y se reenvía tal cual: es lo que permite
     guardar sin volver a teclear el secreto.
  3. **Las tres validaciones de arriba sólo se aplican con el SSO ACTIVADO.**
     Con la casilla desmarcada se puede guardar todo vacío.
  4. **Una tabla vacía viaja como la cadena `"false"`**, no vacía
     (auth.js:2265 y 2280): sale de concatenar un booleano a la query.

Y un orden que es contrato: autoridad, cliente, secreto, scopes, mapa de grupos,
y sólo al final las dos confirmaciones de `http:`. Los avisos de esta pantalla
salen en la PÁGINA, no en un modal: upstream llama a `showAlert` sin destino.
*/

interface Props {
  token: string | null
  onAviso: (a: Aviso) => void
}

interface FilaGrupo {
  remoteGroup: string
  localGroup: string
}

export function Sso({ token, onAviso }: Props) {
  const [cargando, setCargando] = useState(true)
  const [gruposLocales, setGruposLocales] = useState<string[]>([])
  const [enabled, setEnabled] = useState(false)
  const [authority, setAuthority] = useState('')
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [metadata, setMetadata] = useState('')
  const [scopes, setScopes] = useState<string[]>([])
  const [allowSignup, setAllowSignup] = useState(false)
  const [onlyMapped, setOnlyMapped] = useState(false)
  const [groupMap, setGroupMap] = useState<FilaGrupo[]>([])
  const [ocupado, setOcupado] = useState(false)
  const [confirmar, setConfirmar] = useState<null | 'authority' | 'metadata'>(null)

  function aplicar(c: SsoConfig) {
    setEnabled(c.ssoEnabled)
    setAuthority(c.ssoAuthority ?? '')
    setClientId(c.ssoClientId ?? '')
    setClientSecret(c.ssoClientSecret ?? '')
    setMetadata(c.ssoMetadataAddress ?? '')
    setScopes(c.ssoScopes)
    setAllowSignup(c.ssoAllowSignup)
    setOnlyMapped(c.ssoAllowSignupOnlyForMappedUsers)
    setGroupMap(c.ssoGroupMap.map((g) => ({ ...g })))
    // `localGroups` sólo llega en el `get`: si no viene, se conserva el que ya
    // había en vez de vaciar los desplegables del mapa de grupos.
    if (c.localGroups != null) setGruposLocales(c.localGroups)
  }

  const cargar = useCallback(async () => {
    setCargando(true)
    const outcome = await getSsoConfig(token)
    setCargando(false)

    if (outcome.kind !== 'ok') {
      onAviso(avisoDeFallo(outcome))
      return
    }
    aplicar(outcome.data.response)
  }, [token, onAviso])

  useEffect(() => {
    void cargar()
  }, [cargar])

  /*
  `loadAdminSsoConfig` (auth.js:2196-2204): el Redirect URI que hay que dar de
  alta en el proveedor se calcula en el navegador a partir de la URL actual,
  añadiendo `sso/callback` con una sola barra.
  */
  const redirectUri = (() => {
    const base = `${window.location.protocol}//${window.location.host}${window.location.pathname}`
    return base.endsWith('/') ? `${base}sso/callback` : `${base}/sso/callback`
  })()

  function guardar(saltarAuthority = false, saltarMetadata = false) {
    if (enabled && authority === '') {
      onAviso({ type: 'warning', title: 'Missing!', text: 'Please enter the Authority URL.' })
      return
    }
    if (enabled && clientId === '') {
      onAviso({ type: 'warning', title: 'Missing!', text: 'Please enter the Client ID.' })
      return
    }
    if (enabled && clientSecret === '') {
      onAviso({ type: 'warning', title: 'Missing!', text: 'Please enter the Client Secret.' })
      return
    }

    const s = serializarTabla(scopes.map((v): Celda[] => [{ tipo: 'texto', valor: v }]))
    if (!s.ok) {
      onAviso({ type: 'warning', title: s.fallo.title, text: s.fallo.text })
      return
    }

    const g = serializarTabla(
      groupMap.map((f): Celda[] => [
        { tipo: 'texto', valor: f.remoteGroup },
        { tipo: 'texto', valor: f.localGroup },
      ]),
    )
    if (!g.ok) {
      onAviso({ type: 'warning', title: g.fallo.title, text: g.fallo.text })
      return
    }

    if (!saltarAuthority && authority.startsWith('http:')) {
      setConfirmar('authority')
      return
    }
    if (!saltarMetadata && metadata.startsWith('http:')) {
      setConfirmar('metadata')
      return
    }

    void enviar(s.valor === '' ? 'false' : s.valor, g.valor === '' ? 'false' : g.valor)
  }

  async function enviar(ssoScopes: string, ssoGroupMap: string) {
    setOcupado(true)
    const outcome = await setSsoConfig(token, {
      ssoEnabled: String(enabled),
      ssoAuthority: authority,
      ssoClientId: clientId,
      ssoClientSecret: clientSecret,
      ssoMetadataAddress: metadata,
      ssoScopes,
      ssoAllowSignup: String(allowSignup),
      ssoAllowSignupOnlyForMappedUsers: String(onlyMapped),
      ssoGroupMap,
    })
    setOcupado(false)

    if (outcome.kind !== 'ok') {
      onAviso(avisoDeFallo(outcome))
      return
    }
    aplicar(outcome.data.response)
    onAviso({
      type: 'success',
      title: 'SSO Config Saved!',
      text: 'Single Sign-On (SSO) config was saved successfully.',
    })
  }

  if (cargando) return <Loading />

  return (
    <>
      <SectionHeader
        seccion="Administration"
        titulo="Single Sign-On (SSO)"
      />

      {/* Sin leyenda: era el segundo de cuatro «Single Sign-On (SSO)» seguidos
          —título, leyenda, rótulo de la fila y el propio conmutador— antes del
          primer control, y siendo el único bloque no agrupaba nada. */}
      <Panel className={styles.block}>

        <div className={frm.row}>
          <div className={frm.rowLabel}>Single Sign-On (SSO)</div>
          <div className={frm.rowCtl}>
            <Check
              conmutador
              label="Enable Single Sign-On (SSO)"
              checked={enabled}
              onChange={setEnabled}
              help="Enable to allow Single Sign-On (SSO) with OpenID Connect (OIDC)."
            />
          </div>
        </div>

        <Fila
          label="Authority (Issuer)"
          help="The OpenID Connect (OIDC) Authority URL."
          value={authority}
          placeholder="https://auth.example.com"
          onChange={setAuthority}
        />
        <Fila
          label="Client ID"
          help="The OpenID Connect (OIDC) Client ID."
          value={clientId}
          placeholder="client id"
          onChange={setClientId}
        />
        <Fila
          label="Client Secret"
          help="The OpenID Connect (OIDC) Client Secret."
          value={clientSecret}
          placeholder="client secret"
          type="password"
          onChange={setClientSecret}
        />
        <Fila
          label="Metadata Address (Optional)"
          help="The OpenID Connect (OIDC) metadata discovery URL to be used instead of the default one. Configure this option only if the Single Sign-On (SSO) provider uses a different discovery URL."
          value={metadata}
          placeholder="https://auth.example.com/.well-known/openid-configuration"
          onChange={setMetadata}
        />

        <div className={frm.row}>
          <div className={frm.rowLabel}>Scopes</div>
          <div className={frm.rowCtl}>
            <TablaEditable
      className={styles.edit}
              cabecera={
                <>
                  <th>Scope Name</th>
                  <th className={styles.tdel} />
                </>
              }
            >
              {scopes.map((s, i) => (
                // eslint-disable-next-line react/no-array-index-key
                <tr key={i}>
                  <td>
                    <Input
                      aria-label={`Scope Name ${i + 1}`}
                      value={s}
                      onChange={(e) =>
                        setScopes((lista) => lista.map((v, j) => (j === i ? e.target.value : v)))
                      }
                    />
                  </td>
                  <td className={styles.tdel}>
                    <Button
                      variant="danger"
                      onClick={() => setScopes((lista) => lista.filter((_, j) => j !== i))}
                    >
                      Delete
                    </Button>
                  </td>
                </tr>
              ))}
            </TablaEditable>
            <div>
              <Button onClick={() => setScopes((lista) => [...lista, ''])}>Add</Button>
            </div>
            <div className={styles.help}>
              Enter the scopes to be sent to the Single Sign-On (SSO) provider. The scopes{' '}
              <code>openid</code> and <code>profile</code> are mandatory and will be automatically
              added if missing. Add the scope <code>email</code> if you want to use email address as
              the username for all SSO users that sign up for an account.
            </div>
          </div>
        </div>

        <div className={frm.row}>
          <div className={frm.rowLabel}>SSO User Sign Up</div>
          <div className={frm.rowCtl}>
            <div className={styles.group}>
              <Check
                conmutador
                label="Allow New User Sign Up"
                checked={allowSignup}
                onChange={setAllowSignup}
                help="Enable to allow automatically provisioning of user accounts for new users signing in via Single Sign-On (SSO). Keep this option disabled if you do not expect new SSO users to sign up."
              />
              <Check
                conmutador
                label="Allow Sign Up Only For Mapped Users"
                checked={onlyMapped}
                onChange={setOnlyMapped}
                help={
                  <>
                    Enable to allow a new user to sign up via Single Sign-On (SSO) only when the
                    user is a member of at least one Remote Group that is mapped to a Local Group in
                    the <b>Group Map</b> option below. This option allows SSO administrators to
                    restrict SSO users to control who can sign up and get access based on their
                    group memberships.
                  </>
                }
              />
            </div>
          </div>
        </div>

        <div className={frm.row}>
          <div className={frm.rowLabel}>Group Map (Optional)</div>
          <div className={frm.rowCtl}>
            <TablaEditable
      className={styles.edit}
              cabecera={
                <>
                  <th>Remote Group</th>
                  <th>Local Group</th>
                  <th className={styles.tdel} />
                </>
              }
            >
              {groupMap.map((f, i) => (
                // eslint-disable-next-line react/no-array-index-key
                <tr key={i}>
                  <td>
                    <Input
                      aria-label={`Remote Group ${i + 1}`}
                      value={f.remoteGroup}
                      onChange={(e) =>
                        setGroupMap((lista) =>
                          lista.map((x, j) =>
                            j === i ? { ...x, remoteGroup: e.target.value } : x,
                          ),
                        )
                      }
                    />
                  </td>
                  <td>
                    <Select
                      className={styles.select}
                      aria-label={`Local Group ${i + 1}`}
                      value={f.localGroup}
                      onChange={(e) =>
                        setGroupMap((lista) =>
                          lista.map((x, j) => (j === i ? { ...x, localGroup: e.target.value } : x)),
                        )
                      }
                    >
                      {gruposLocales.map((g) => (
                        <option key={g} value={g}>
                          {g}
                        </option>
                      ))}
                    </Select>
                  </td>
                  <td className={styles.tdel}>
                    <Button
                      variant="danger"
                      onClick={() => setGroupMap((lista) => lista.filter((_, j) => j !== i))}
                    >
                      Delete
                    </Button>
                  </td>
                </tr>
              ))}
            </TablaEditable>
            <div>
              <Button
                onClick={() =>
                  setGroupMap((lista) => [
                    ...lista,
                    { remoteGroup: '', localGroup: gruposLocales[0] ?? '' },
                  ])
                }
              >
                Add
              </Button>
            </div>
            <div className={styles.help}>
              Map Remote Groups at Single Sign-On (SSO) provider to Local Groups for both new and
              existing users signed up via Single Sign-On (SSO). A SSO user&apos;s group membership
              will be automatically synced to the mapped Local Groups each time they log in. If your
              SSO provider does not include group membership claim by default then you will have to
              add <code>groups</code> or <code>roles</code> scope in the <b>Scopes</b> option above
              as required by the SSO provider.
            </div>
          </div>
        </div>

        <div className={styles.notas}>
          <Alert type="info" title="Note!">
            The Single Sign-On (SSO) uses <code>/sso/callback</code> as the callback path. Thus, your
            SSO Redirect URI for this DNS Server should be <code>{redirectUri}</code> which needs to
            be configure with the SSO provider.
          </Alert>
          <Alert type="info" title="Note!">
            Single Sign-On (SSO) will be enabled only when all of the required parameters are
            configured correctly. If SSO does not work for any reason, check the Logs section on the
            panel and search for related error logs.
          </Alert>
          <Alert type="info" title="Note!">
            When a Single Sign-On (SSO) user signs up with the DNS Server, an account for the user is
            created which uses the email address as the username. If email address is not available,
            the preferred username is used instead. If you do not wish to use email address as the
            username, you can remove the <code>email</code> scope from the <b>Scopes</b> option
            above.
          </Alert>
          <Alert type="info" title="Note!">
            The Single Sign-On (SSO) user&apos;s Display Name and Username are managed via the SSO
            provider and they are automatically synced each time a user logs in.
          </Alert>
          <Alert type="info" title="Note!">
            When Group Map is configured, the Single Sign-On (SSO) user&apos;s group membership
            cannot be managed locally and any group membership changes must be configured at the SSO
            provider itself. SSO users need to relogin so that any group membership changes made at
            SSO provider are applied to their user accounts. The Group Map thus allows managing user
            access centrally via the SSO provider. Keep the Group Map empty if group membership
            management for SSO users is required to be managed via the DNS Server itself.
          </Alert>
          <Alert type="info" title="Note!">
            The Web Service will be automatically restarted to apply these changes thus there is no
            need to restart the DNS Server manually.
          </Alert>
          <Alert type="info" title="Note!">
            When using a reverse proxy with the Web Service, you need to add{' '}
            <code>X-Forwarded-Proto</code> and <code>X-Forwarded-Host</code> headers to proxy request
            to allow the Web Service to correctly form the SSO Redirect URI. If the reverse proxy is
            setup to use a path prefix then make sure to add the <code>X-Forwarded-Prefix</code>{' '}
            header to proxy request too. These headers will be read only if the reverse proxy IP
            address is configured to be allowed in the <b>Reverse Proxy Addresses</b> option in
            Settings &gt; Web Service section. For example, if you are using nginx as the reverse
            proxy with a path prefix of <code>/dns</code>, then you should add the following headers:{' '}
            <code>proxy_set_header X-Forwarded-Proto $scheme;</code>,{' '}
            <code>proxy_set_header X-Forwarded-Host $host;</code>,{' '}
            <code>proxy_set_header X-Forwarded-Prefix /dns;</code>, and{' '}
            <code>proxy_redirect / /dns/;</code>
          </Alert>
          <Alert type="info" title="Note!">
            Domain names in all of the URLs configured above will be resolved by the DNS Server
            internally only. Thus, make sure that the DNS Server is able to resolve the domain name
            in the URL. Adding <code>hosts</code> file entries in the host OS will not work.
          </Alert>
          <Alert type="warning" title="Warning!">
            All URLs configured above must use <code>https</code> URL scheme for production
            environments. Using <code>http</code> URL scheme is not secure and should be used only
            for testing purposes.
          </Alert>
          <Alert type="warning" title="Warning!">
            Any DNS related failure may cause Single Sign-On (SSO) to fail to work making it
            impossible for SSO users to log in to fix the DNS issue due to circular dependency. Thus,
            it is recommended to maintain a local administrator user account for such scenarios.
          </Alert>
        </div>
      </Panel>

      <div className={styles.bar}>
        <Button variant="primary" disabled={ocupado} onClick={() => guardar()}>
          Save Config
        </Button>
      </div>

      <Confirmar
        abierto={confirmar === 'authority'}
        titulo="Save Config"
        texto="WARNING! The SSO Authority must use a 'https' URL scheme for production environment. Are you sure you want to proceed with using a 'http' URL scheme?"
        etiqueta="OK"
        variante="primary"
        onCerrar={() => setConfirmar(null)}
        onConfirmar={() => {
          setConfirmar(null)
          guardar(true)
        }}
      />
      <Confirmar
        abierto={confirmar === 'metadata'}
        titulo="Save Config"
        texto="WARNING! The Metadata Address must use a 'https' URL scheme for production environment. Are you sure you want to proceed with using a 'http' URL scheme?"
        etiqueta="OK"
        variante="primary"
        onCerrar={() => setConfirmar(null)}
        onConfirmar={() => {
          setConfirmar(null)
          guardar(true, true)
        }}
      />
    </>
  )
}

/** Fila etiqueta + control con la misma rejilla que Settings (210 px), para
 *  que las dos pantallas de formulario de la consola se lean igual. */
function Fila({
  label,
  help,
  value,
  placeholder,
  type,
  onChange,
}: {
  label: string
  help: string
  value: string
  placeholder: string
  type?: 'password'
  onChange: (v: string) => void
}) {
  const id = useId()
  return (
    <div className={frm.row}>
      <label className={frm.rowLabel} htmlFor={id}>
        {label}
      </label>
      <div className={frm.rowCtl}>
        <Input
          id={id}
          type={type}
          value={value}
          placeholder={placeholder}
          maxLength={255}
          onChange={(e) => onChange(e.target.value)}
          style={{ width: '100%', maxWidth: 420 }}
        />
        <div className={styles.help}>{help}</div>
      </div>
    </div>
  )
}
