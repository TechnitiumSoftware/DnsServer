import { useCallback, useEffect, useState } from 'react'
import { apiRequest, avisarSiCaducaLaSesion } from '../api/client'
import { Login, type Session } from '../screens/Login'
import { Shell, type ShellSession } from '../app/Shell'
import { readBootIntent } from './boot'

type State =
  | { phase: 'booting' }
  | { phase: 'login'; alert?: { type: 'danger'; title: string; text: string } }
  | { phase: 'ready'; session: ShellSession }

export function SessionProvider() {
  const [state, setState] = useState<State>({ phase: 'booting' })

  useEffect(() => {
    const intent = readBootIntent()

    if (intent.kind === 'show-error') {
      setState({ phase: 'login', alert: { type: 'danger', title: 'Error!', text: intent.message } })
      return
    }

    if (intent.kind === 'show-login') {
      setState({ phase: 'login' })
      return
    }

    let cancelled = false
    void (async () => {
      const outcome = await apiRequest<ShellSession>('user/session/get', { token: intent.token })
      if (cancelled) return
      if (outcome.kind === 'ok') {
        localStorage.setItem('token', outcome.data.token)
        setState({ phase: 'ready', session: outcome.data })
      } else {
        setState({ phase: 'login' })
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  /*
  Si el servidor rechaza la sesión en CUALQUIER llamada, se acaba aquí: se borra
  el token y se vuelve al login, como hace upstream. Sin esto, la consola se
  quedaba en pie con una sesión muerta.
  */
  useEffect(() => {
    avisarSiCaducaLaSesion(() => {
      localStorage.removeItem('token')
      setState((anterior) =>
        anterior.phase === 'login'
          ? anterior
          : {
              phase: 'login',
              alert: { type: 'danger', title: 'Error!', text: 'Session expired. Please login again.' },
            },
      )
    })
    return () => avisarSiCaducaLaSesion(null)
  }, [])

  const onSuccess = useCallback((session: Session) => {
    localStorage.setItem('token', session.token)
    setState({ phase: 'ready', session: session as ShellSession })
  }, [])

  // auth.js:299-312 — la sesión se limpia tanto si la llamada va bien como si falla.
  const onLogout = useCallback(async () => {
    const token = localStorage.getItem('token')
    await apiRequest('user/logout', { token })
    localStorage.removeItem('token')
    setState({ phase: 'login' })
  }, [])

  if (state.phase === 'booting') return null
  if (state.phase === 'login') return <Login onSuccess={onSuccess} initialAlert={state.alert} />
  return <Shell session={state.session} onLogout={() => void onLogout()} />
}
