import { useId, type InputHTMLAttributes, type ReactNode } from 'react'
import styles from './Field.module.css'

export function Field({ label, children }: { label: string; children: (id: string) => ReactNode }) {
  const id = useId()
  return (
    <div className={styles.field}>
      <label className={styles.label} htmlFor={id}>
        {label}
      </label>
      {children(id)}
    </div>
  )
}

export function Input({
  mono,
  className,
  ...rest
}: InputHTMLAttributes<HTMLInputElement> & { mono?: boolean }) {
  return (
    <input
      className={[styles.input, mono ? styles.mono : '', className].filter(Boolean).join(' ')}
      {...rest}
    />
  )
}

/** Campo con etiqueta asociada por `htmlFor`, que es lo que permite consultarlo
 *  en las pruebas con `getByLabelText` igual que lo haría un lector de pantalla. */
export function LabeledInput({
  label,
  mono,
  ...rest
}: InputHTMLAttributes<HTMLInputElement> & { label: string; mono?: boolean }) {
  return <Field label={label}>{(id) => <Input id={id} mono={mono} {...rest} />}</Field>
}
