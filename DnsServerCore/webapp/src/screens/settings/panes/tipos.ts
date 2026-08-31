import type { SettingsForm } from '../model'
import { habilitado } from '../model'

/** Props common to the nine sub-tabs. `en` are the enablement rules already
 *  derived from the state (see `habilitado` in model.ts). */
export interface PaneProps {
  f: SettingsForm
  set: (parcial: Partial<SettingsForm>) => void
  en: ReturnType<typeof habilitado>
}
