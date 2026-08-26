import { screen, within } from '@testing-library/react'
import type { UserEvent } from '@testing-library/user-event'

/*
El desplegable de la consola es `ui/Select`, un listbox propio y no un `<select>`
nativo, así que `userEvent.selectOptions` no le vale: no hay `<option>` que
seleccionar, hay una lista que se abre y una línea que se pulsa.

Esto hace lo que haría una persona: abrir y elegir. Y de paso comprueba lo que
`selectOptions` no comprobaba, que la lista se abre de verdad.
*/
export async function elegir(user: UserEvent, disparador: HTMLElement, etiqueta: string | RegExp) {
  await user.click(disparador)
  const lista = await screen.findByRole('listbox')
  await user.click(within(lista).getByRole('option', { name: etiqueta }))
}

/** El mismo, buscando el disparador por su etiqueta. */
export async function elegirEn(user: UserEvent, campo: string | RegExp, etiqueta: string | RegExp) {
  await elegir(user, screen.getByLabelText(campo), etiqueta)
}

/** Las opciones que ofrece un desplegable, en orden. Lo abre y lo vuelve a cerrar. */
export async function opcionesDe(user: UserEvent, disparador: HTMLElement): Promise<string[]> {
  await user.click(disparador)
  const lista = await screen.findByRole('listbox')
  const textos = within(lista)
    .getAllByRole('option')
    .map((o) => o.textContent?.trim() ?? '')
  await user.keyboard('{Escape}')
  return textos
}

/** Lo que enseña el desplegable ahora mismo, sin abrirlo. */
export function valorDe(disparador: HTMLElement): string {
  return disparador.textContent?.trim() ?? ''
}
