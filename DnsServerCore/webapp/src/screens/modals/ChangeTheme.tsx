import { Button } from '../../ui/Button'
import { Dialog } from '../../ui/Dialog'
import { THEMES, useTheme, type Theme } from '../../theme/ThemeProvider'

const LABELS: Record<Theme, string> = { dark: 'Dark', light: 'Light', amber: 'Amber' }

/* Los tres temas de upstream. Cliente puro: no toca ningún endpoint. */
export function ChangeTheme({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
}) {
  const { theme, setTheme } = useTheme()
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Change Theme"
      footer={<Button onClick={() => onOpenChange(false)}>Close</Button>}
    >
      {THEMES.map((t) => (
        <label key={t} style={{ display: 'flex', alignItems: 'center', gap: 9, fontSize: 12.5 }}>
          <input
            type="radio"
            name="theme"
            checked={theme === t}
            onChange={() => setTheme(t)}
            style={{ accentColor: 'var(--acc)', width: 15, height: 15 }}
          />
          {LABELS[t]}
        </label>
      ))}
    </Dialog>
  )
}
