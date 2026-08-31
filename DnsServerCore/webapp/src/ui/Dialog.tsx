import * as RadixDialog from '@radix-ui/react-dialog'
import type { ReactNode } from 'react'
import { Button } from './Button'
import { Icon } from './Icon'
import styles from './Dialog.module.css'

/*
The footer is NOT free text. When it was, 23 modals put the action first and 17
put it last, and in five of them the action was destructive: `Delete` and `Close`
swapped places between two dialogs on the same screen.

Here the order belongs to the component, not to whoever uses it:

    [ actions … ] [ Close ]

`acciones` are the buttons that DO something; the dismiss one is painted by
`Dialog` and always goes last, in the corner upstream had it in all 40 of its
modals. That way no new modal can pick its own order again.
*/

export function Dialog({
  open,
  onOpenChange,
  title,
  children,
  actions,
  close = 'Close',
  size = 'form',
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  children: ReactNode
  /** The buttons that do something. The dismiss one is not passed: Dialog adds it. */
  actions?: ReactNode
  /** Label for the dismiss button. `Cancel` when the modal is a question. */
  close?: string
  /**
   * The size, decided by the CONTENT and not by taste:
   *
   * · `compacto` — a question and two buttons. The longest confirmation literal
   *   in the console measures 405 px in the real typeface, so at 440 they all fit
   *   on one line. Upstream does not have this size because its confirmations are
   *   the browser's `confirm()`.
   * · `formulario` — fields with their labels. The ones upstream leaves at 600.
   * · `medio` — long forms and narrow tables. Upstream's 750-800.
   * · `ancho` — real tables. Upstream's 940.
   *
   * The steps are upstream's, which did decide modal by modal; the figures are
   * lower because our typography runs tighter.
   */
  size?: 'compact' | 'form' | 'medium' | 'wide'
}) {
  return (
    <RadixDialog.Root open={open} onOpenChange={onOpenChange}>
      <RadixDialog.Portal>
        <RadixDialog.Overlay className={styles.overlay} />
        <RadixDialog.Content
          className={`${styles.content} ${styles[size]}`}
          data-size={size}
        >
          <div className={styles.head}>
            <RadixDialog.Title className={styles.title}>{title}</RadixDialog.Title>
            <RadixDialog.Close className={styles.close} aria-label="Close">
              <Icon name="close" tam={16} />
            </RadixDialog.Close>
          </div>
          <div className={styles.body}>{children}</div>
          <div className={styles.foot}>
            {actions}
            <Button onClick={() => onOpenChange(false)}>{close}</Button>
          </div>
        </RadixDialog.Content>
      </RadixDialog.Portal>
    </RadixDialog.Root>
  )
}
