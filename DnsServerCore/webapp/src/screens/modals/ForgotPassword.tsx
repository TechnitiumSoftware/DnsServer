import { Dialog } from '../../ui/Dialog'
import styles from './ForgotPassword.module.css'

/*
`modalForgotPassword` (index.html:3864). It calls no endpoint: it is text.

And it is needed all the same, because it explains the ONLY procedure that exists
for recovering access —renaming `auth.config` to `resetadmin.config` and
restarting— and without it an administrator who loses the password is locked out
without knowing the way back exists. The text is copied literally: they are
operating instructions, not prose of ours.

It was found missing in the phase 10 inventory sweep: it was the only one of
upstream's 40 modals with no counterpart.
*/

export function ForgotPassword({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      tamano="medio"
      title="Forgot Password?"
    >
      <p className={styles.parrafo}>
        To reset your password, you need to contact the DNS Server administrator.
      </p>
      <p className={styles.parrafo}>
        If you are an administrator, follow these steps to reset the &apos;admin&apos; user&apos;s
        password:
      </p>
      <ol className={styles.pasos}>
        <li>Stop the DNS Server.</li>
        <li>
          Find the DNS Server config folder and locate the <b>auth.config</b> file. The config folder
          will be found where the DNS Server is installed on Windows or /etc/dns/ folder on Linux.
        </li>
        <li>
          Rename the <b>auth.config</b> file as <b>resetadmin.config</b>
        </li>
        <li>Start the DNS Server.</li>
        <li>
          Just refresh this web page in the web browser to auto login with default credentials and
          quickly change the password.
        </li>
      </ol>
      <p className={styles.parrafo}>
        On Linux, stop the DNS Server by running &apos;sudo systemctl stop dns&apos; command and
        &apos;sudo systemctl start dns&apos; command to start it.
      </p>
      <p className={styles.parrafo}>
        On Windows, press Win+R to open Run, enter &apos;services.msc&apos;, and press enter to open
        Services console. Find service named &apos;Technitium DNS Server&apos; and use the Action menu
        to start/stop it.
      </p>
      <p className={styles.parrafo}>
        <b>Note: </b>To reset &apos;admin&apos; password, you will need file system access on the
        server running this DNS Server. If the &apos;admin&apos; user does not exists then it will be
        created automatically. If the &apos;admin&apos; user has Two-factor Authentication (2FA)
        configured then it will be disabled too.
      </p>
    </Dialog>
  )
}
