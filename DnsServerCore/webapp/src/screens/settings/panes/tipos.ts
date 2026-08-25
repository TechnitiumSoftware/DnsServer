import type { SettingsForm } from '../model'
import { habilitado } from '../model'

/** Props comunes a las nueve sub-pestañas. `en` son las reglas de habilitado ya
 *  derivadas del estado (ver `habilitado` en model.ts). */
export interface PaneProps {
  f: SettingsForm
  set: (parcial: Partial<SettingsForm>) => void
  en: ReturnType<typeof habilitado>
}
