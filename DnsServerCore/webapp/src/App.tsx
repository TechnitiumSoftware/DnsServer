import { ThemeProvider } from './theme/ThemeProvider'
import { SessionProvider } from './session/SessionProvider'

export default function App() {
  return (
    <ThemeProvider>
      <SessionProvider />
    </ThemeProvider>
  )
}
