import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Sso } from './Sso'
import * as client from '../../api/client'
import { SSO } from './admin.fixture'
import { opcionesDe } from '../../test/desplegable'

afterEach(() => vi.restoreAllMocks())

const ok = (data: unknown) => ({ kind: 'ok' as const, data })

function servidor(overrides: Record<string, unknown> = {}, respuestaSet?: Record<string, unknown>) {
  return vi.spyOn(client, 'apiRequest').mockImplementation(async (path: string) => {
    if (path === 'admin/sso/get') return ok({ response: { ...SSO, ...overrides }, server: 'x' })
    if (path === 'admin/sso/set') {
      // El `set` NO devuelve `localGroups`: es la respuesta literal de la
      // instancia de referencia.
      const { localGroups: _sinGrupos, ...resto } = { ...SSO, ...overrides }
      return ok({ response: respuestaSet ?? resto, server: 'x' })
    }
    return ok({ response: {}, server: 'x' })
  })
}

const props = { token: 'tok', onAviso: vi.fn() }

const cuerpo = (spy: ReturnType<typeof servidor>) =>
  spy.mock.calls.find((c) => c[0] === 'admin/sso/set')?.[1]?.body as Record<string, string>

describe('SSO — carga', () => {
  it('pinta los scopes que trae el servidor y las dos casillas de alta', async () => {
    servidor()
    render(<Sso {...props} />)
    expect(await screen.findByLabelText('Scope Name 1')).toHaveValue('openid')
    expect(screen.getByLabelText('Scope Name 3')).toHaveValue('email')
    expect(screen.getByLabelText('Allow Sign Up Only For Mapped Users')).toBeChecked()
  })

  it('los campos nulos del servidor se pintan vacíos, no como «null»', async () => {
    servidor()
    render(<Sso {...props} />)
    expect(await screen.findByLabelText('Authority (Issuer)')).toHaveValue('')
    expect(screen.getByLabelText('Client Secret')).toHaveValue('')
  })

  it('el secreto ya guardado llega enmascarado y se conserva tal cual', async () => {
    const spy = servidor({ ssoClientSecret: '************' })
    const user = userEvent.setup()
    render(<Sso {...props} />)

    expect(await screen.findByLabelText('Client Secret')).toHaveValue('************')
    await user.click(screen.getByRole('button', { name: 'Save Config' }))
    expect(cuerpo(spy).ssoClientSecret).toBe('************')
  })
})

describe('SSO — validaciones', () => {
  it('con el SSO apagado se puede guardar todo vacío', async () => {
    const spy = servidor()
    const user = userEvent.setup()
    render(<Sso {...props} />)

    await screen.findByLabelText('Authority (Issuer)')
    await user.click(screen.getByRole('button', { name: 'Save Config' }))
    expect(cuerpo(spy).ssoEnabled).toBe('false')
  })

  it('con el SSO encendido el orden es autoridad, cliente y secreto', async () => {
    const onAviso = vi.fn()
    const spy = servidor()
    const user = userEvent.setup()
    render(<Sso {...props} onAviso={onAviso} />)

    await user.click(await screen.findByLabelText('Enable Single Sign-On (SSO)'))
    const guardar = screen.getByRole('button', { name: 'Save Config' })

    await user.click(guardar)
    expect(onAviso).toHaveBeenLastCalledWith({
      type: 'warning',
      title: 'Missing!',
      text: 'Please enter the Authority URL.',
    })

    await user.type(screen.getByLabelText('Authority (Issuer)'), 'https://id.test')
    await user.click(guardar)
    expect(onAviso).toHaveBeenLastCalledWith({
      type: 'warning',
      title: 'Missing!',
      text: 'Please enter the Client ID.',
    })

    await user.type(screen.getByLabelText('Client ID'), 'technitium')
    await user.click(guardar)
    expect(onAviso).toHaveBeenLastCalledWith({
      type: 'warning',
      title: 'Missing!',
      text: 'Please enter the Client Secret.',
    })

    expect(spy.mock.calls.find((c) => c[0] === 'admin/sso/set')).toBeUndefined()
  })

  it('un scope vacío aborta el guardado con el aviso de la tabla', async () => {
    const onAviso = vi.fn()
    const spy = servidor()
    const user = userEvent.setup()
    render(<Sso {...props} onAviso={onAviso} />)

    // There are two "Add": the scopes one and the group map one. Upstream labels
    // both the same; the first is used here, which is the scopes one.
    await screen.findByLabelText('Scope Name 1')
    await user.click(screen.getAllByRole('button', { name: 'Add' })[0])
    await user.click(screen.getByRole('button', { name: 'Save Config' }))

    expect(onAviso).toHaveBeenLastCalledWith({
      type: 'warning',
      title: 'Missing!',
      text: 'Please enter a valid value in the text field in focus.',
    })
    expect(spy.mock.calls.find((c) => c[0] === 'admin/sso/set')).toBeUndefined()
  })

  it('un `|` en un scope aborta con su propio aviso', async () => {
    const onAviso = vi.fn()
    servidor()
    const user = userEvent.setup()
    render(<Sso {...props} onAviso={onAviso} />)

    await user.type(await screen.findByLabelText('Scope Name 1'), '|x')
    await user.click(screen.getByRole('button', { name: 'Save Config' }))

    expect(onAviso).toHaveBeenLastCalledWith({
      type: 'warning',
      title: 'Invalid Character!',
      text: "Please edit the value in the text field in focus to remove '|' character.",
    })
  })
})

describe('SSO — el envío', () => {
  it('los scopes viajan unidos por `|`', async () => {
    const spy = servidor()
    const user = userEvent.setup()
    render(<Sso {...props} />)

    await screen.findByLabelText('Scope Name 1')
    await user.click(screen.getByRole('button', { name: 'Save Config' }))
    expect(cuerpo(spy).ssoScopes).toBe('openid|profile|email')
  })

  it('una lista vacía viaja como la cadena «false», no vacía', async () => {
    const spy = servidor({ ssoScopes: [] })
    const user = userEvent.setup()
    render(<Sso {...props} />)

    await screen.findByLabelText('Authority (Issuer)')
    await user.click(screen.getByRole('button', { name: 'Save Config' }))
    expect(cuerpo(spy).ssoScopes).toBe('false')
    expect(cuerpo(spy).ssoGroupMap).toBe('false')
  })

  it('el mapa de grupos viaja con las dos columnas por fila', async () => {
    const spy = servidor({ ssoGroupMap: [{ remoteGroup: 'dns-admins', localGroup: 'Administrators' }] })
    const user = userEvent.setup()
    render(<Sso {...props} />)

    expect(await screen.findByLabelText('Remote Group 1')).toHaveValue('dns-admins')
    await user.click(screen.getByRole('button', { name: 'Save Config' }))
    expect(cuerpo(spy).ssoGroupMap).toBe('dns-admins|Administrators')
  })

  it('avisa con el literal de upstream al guardar', async () => {
    const onAviso = vi.fn()
    servidor()
    const user = userEvent.setup()
    render(<Sso {...props} onAviso={onAviso} />)

    await screen.findByLabelText('Authority (Issuer)')
    await user.click(screen.getByRole('button', { name: 'Save Config' }))

    expect(onAviso).toHaveBeenLastCalledWith({
      type: 'success',
      title: 'SSO Config Saved!',
      text: 'Single Sign-On (SSO) config was saved successfully.',
    })
  })

  it('la respuesta del guardado NO trae los grupos locales y no se pierden', async () => {
    servidor({ ssoGroupMap: [{ remoteGroup: 'g', localGroup: 'Administrators' }] })
    const user = userEvent.setup()
    render(<Sso {...props} />)

    await screen.findByLabelText('Remote Group 1')
    await user.click(screen.getByRole('button', { name: 'Save Config' }))

    expect(await opcionesDe(user, await screen.findByLabelText('Local Group 1'))).toHaveLength(3)
  })
})

describe('SSO — las dos confirmaciones de `http:`', () => {
  it('una autoridad con `http:` pide confirmación antes de guardar', async () => {
    const spy = servidor({ ssoAuthority: 'http://id.test' })
    const user = userEvent.setup()
    render(<Sso {...props} />)

    await screen.findByLabelText('Authority (Issuer)')
    await user.click(screen.getByRole('button', { name: 'Save Config' }))

    expect(
      screen.getByText(
        "WARNING! The SSO Authority must use a 'https' URL scheme for production environment. Are you sure you want to proceed with using a 'http' URL scheme?",
      ),
    ).toBeInTheDocument()
    expect(spy.mock.calls.find((c) => c[0] === 'admin/sso/set')).toBeUndefined()

    await user.click(screen.getByRole('button', { name: 'OK' }))
    expect(cuerpo(spy).ssoAuthority).toBe('http://id.test')
  })

  it('cancelar la confirmación no manda nada', async () => {
    const spy = servidor({ ssoAuthority: 'http://id.test' })
    const user = userEvent.setup()
    render(<Sso {...props} />)

    await screen.findByLabelText('Authority (Issuer)')
    await user.click(screen.getByRole('button', { name: 'Save Config' }))
    await user.click(screen.getByRole('button', { name: 'Cancel' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/sso/set')).toBeUndefined()
  })

  it('la del Metadata Address es la segunda y tiene su propio texto', async () => {
    const spy = servidor({ ssoMetadataAddress: 'http://id.test/.well-known/openid-configuration' })
    const user = userEvent.setup()
    render(<Sso {...props} />)

    await screen.findByLabelText('Metadata Address (Optional)')
    await user.click(screen.getByRole('button', { name: 'Save Config' }))

    expect(
      screen.getByText(
        "WARNING! The Metadata Address must use a 'https' URL scheme for production environment. Are you sure you want to proceed with using a 'http' URL scheme?",
      ),
    ).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'OK' }))
    expect(cuerpo(spy)).toBeTruthy()
  })
})
