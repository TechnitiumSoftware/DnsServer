import { screen, within } from '@testing-library/react'
import type { UserEvent } from '@testing-library/user-event'

/*
The console's dropdown is `ui/Select`, a listbox of our own and not a native
`<select>`, so `userEvent.selectOptions` is no use to it: there is no `<option>`
to select, there is a list that opens and a line that gets pressed.

This does what a person would do: open and choose. And along the way it checks
what `selectOptions` was not checking, that the list really does open.
*/
export async function choose(user: UserEvent, disparador: HTMLElement, etiqueta: string | RegExp) {
  await user.click(disparador)
  const list = await screen.findByRole('listbox')
  await user.click(within(list).getByRole('option', { name: etiqueta }))
}

/** The same, finding the trigger by its label. */
export async function chooseIn(user: UserEvent, field: string | RegExp, etiqueta: string | RegExp) {
  await choose(user, screen.getByLabelText(field), etiqueta)
}

/** The options a dropdown offers, in order. It opens it and closes it again. */
export async function opcionesDe(user: UserEvent, disparador: HTMLElement): Promise<string[]> {
  await user.click(disparador)
  const list = await screen.findByRole('listbox')
  const textos = within(list)
    .getAllByRole('option')
    .map((o) => o.textContent?.trim() ?? '')
  await user.keyboard('{Escape}')
  return textos
}

/** What the dropdown is showing right now, without opening it. */
export function valorDe(disparador: HTMLElement): string {
  return disparador.textContent?.trim() ?? ''
}
