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
  it('it draws the scopes the server brings and the two sign-up checkboxes', async () => {
    servidor()
    render(<Sso {...props} />)
    expect(await screen.findByLabelText('Scope Name 1')).toHaveValue('openid')
    expect(screen.getByLabelText('Scope Name 3')).toHaveValue('email')
    expect(screen.getByLabelText('Allow Sign Up Only For Mapped Users')).toBeChecked()
  })

  it('the null fields from the server are drawn empty, not as \"null\"', async () => {
    servidor()
    render(<Sso {...props} />)
    expect(await screen.findByLabelText('Authority (Issuer)')).toHaveValue('')
    expect(screen.getByLabelText('Client Secret')).toHaveValue('')
  })

  it('the stored secret arrives masked and is kept as it is', async () => {
    const spy = servidor({ ssoClientSecret: '************' })
    const user = userEvent.setup()
    render(<Sso {...props} />)

    expect(await screen.findByLabelText('Client Secret')).toHaveValue('************')
    await user.click(screen.getByRole('button', { name: 'Save Config' }))
    expect(cuerpo(spy).ssoClientSecret).toBe('************')
  })
})

describe('SSO — validaciones', () => {
  it('with SSO off everything can be saved empty', async () => {
    const spy = servidor()
    const user = userEvent.setup()
    render(<Sso {...props} />)

    await screen.findByLabelText('Authority (Issuer)')
    await user.click(screen.getByRole('button', { name: 'Save Config' }))
    expect(cuerpo(spy).ssoEnabled).toBe('false')
  })

  it('with SSO on the order is authority, client and secret', async () => {
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

  it('an empty scope aborts the save with the table alert', async () => {
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

  it('a `|` in a scope aborts with its own alert', async () => {
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

describe('SSO — the send', () => {
  it('the scopes travel joined by `|`', async () => {
    const spy = servidor()
    const user = userEvent.setup()
    render(<Sso {...props} />)

    await screen.findByLabelText('Scope Name 1')
    await user.click(screen.getByRole('button', { name: 'Save Config' }))
    expect(cuerpo(spy).ssoScopes).toBe('openid|profile|email')
  })

  it('an empty list travels as the string \"false\", not empty', async () => {
    const spy = servidor({ ssoScopes: [] })
    const user = userEvent.setup()
    render(<Sso {...props} />)

    await screen.findByLabelText('Authority (Issuer)')
    await user.click(screen.getByRole('button', { name: 'Save Config' }))
    expect(cuerpo(spy).ssoScopes).toBe('false')
    expect(cuerpo(spy).ssoGroupMap).toBe('false')
  })

  it('the group map travels with both columns per row', async () => {
    const spy = servidor({ ssoGroupMap: [{ remoteGroup: 'dns-admins', localGroup: 'Administrators' }] })
    const user = userEvent.setup()
    render(<Sso {...props} />)

    expect(await screen.findByLabelText('Remote Group 1')).toHaveValue('dns-admins')
    await user.click(screen.getByRole('button', { name: 'Save Config' }))
    expect(cuerpo(spy).ssoGroupMap).toBe('dns-admins|Administrators')
  })

  it('it alerts with the upstream literal on saving', async () => {
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

  it('the save response does NOT bring the local groups and they are not lost', async () => {
    servidor({ ssoGroupMap: [{ remoteGroup: 'g', localGroup: 'Administrators' }] })
    const user = userEvent.setup()
    render(<Sso {...props} />)

    await screen.findByLabelText('Remote Group 1')
    await user.click(screen.getByRole('button', { name: 'Save Config' }))

    expect(await opcionesDe(user, await screen.findByLabelText('Local Group 1'))).toHaveLength(3)
  })
})

describe('SSO — the two `http:` confirmations', () => {
  it('an authority with `http:` asks for confirmation before saving', async () => {
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

  it('cancelling the confirmation sends nothing', async () => {
    const spy = servidor({ ssoAuthority: 'http://id.test' })
    const user = userEvent.setup()
    render(<Sso {...props} />)

    await screen.findByLabelText('Authority (Issuer)')
    await user.click(screen.getByRole('button', { name: 'Save Config' }))
    await user.click(screen.getByRole('button', { name: 'Cancel' }))

    expect(spy.mock.calls.find((c) => c[0] === 'admin/sso/set')).toBeUndefined()
  })

  it('the Metadata Address one is the second and has its own text', async () => {
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
