import { Notices, Block, Check, GroupRow, Radios, TextRow, Warning } from '../parts'
import type { PaneProps } from './types'

/* Settings > Logging (index.html:2359-2476). Dos bloques. */
export function Logging({ f, set, en }: PaneProps) {
  return (
    <>
      {/* No legend: it repeated the panel's title. */}
      <Block>
        <GroupRow label="Enable Logging To">
          <Radios
            name="rdLoggingType"
            value={f.loggingType}
            onChange={(v) => set({ loggingType: v })}
            options={[
              {
                value: 'None',
                label: 'None',
                help: 'Disables all logging including error logs and audit logs.',
              },
              {
                value: 'File',
                label: 'File',
                help: 'Enables logging errors and audit logs to the log file.',
              },
              {
                value: 'Console',
                label: 'Console',
                help: 'Enables logging errors and audit logs to the console.',
              },
              {
                value: 'FileAndConsole',
                label: 'Both File And Console',
                help: 'Enables logging errors and audit logs to both the log file and console.',
              },
            ]}
          />
        </GroupRow>

        <GroupRow label="Logging Options">
          <Check
            toggle
            label="Ignore Resolver Error Logs"
            checked={f.ignoreResolverLogs}
            onChange={(v) => set({ ignoreResolverLogs: v })}
            disabled={!en.logging}
            help="Enable this option to stop logging domain name resolution errors."
          />
          <Check
            toggle
            label="No Stack Trace"
            checked={f.noStackTrace}
            onChange={(v) => set({ noStackTrace: v })}
            disabled={!en.logging}
            help="Enable to log only short error messages instead of full exception stack trace."
          />
          <Check
            toggle
            label="Log All Queries"
            checked={f.logQueries}
            onChange={(v) => set({ logQueries: v })}
            disabled={!en.logging}
            help="Enable this option to log every query received by this DNS Server and the corresponding response answers into the log file."
          />
          <Check
            toggle
            label="Use Local Time"
            checked={f.useLocalTime}
            onChange={(v) => set({ useLocalTime: v })}
            disabled={!en.logging}
            help="Enable this option to use local time instead of UTC for logging."
          />
        </GroupRow>

        <TextRow
          label="Log Folder Path"
          value={f.logFolder}
          onChange={(v) => set({ logFolder: v })}
          placeholder="Log Folder Path On Server"
          maxLength={255}
          width="wide"
          disabled={!en.logging}
          help="The folder path on the server where the log files should be saved. The path can be relative to the DNS Server's config folder."
        />
        <TextRow
          label="Max Log File Days"
          type="number"
          value={f.maxLogFileDays}
          onChange={(v) => set({ maxLogFileDays: v })}
          placeholder="Max Days"
          suffix="days (default 365, set 0 to disable auto delete)"
          help="Max number of days to keep the log files. Log files older than the specified number of days will be deleted automatically."
        />
        <Notices>
          <Warning>
            Enabling query logging will significantly increase the log file size and use up disk
            space.
          </Warning>
        </Notices>
      </Block>

      <Block title="Stats">
        <GroupRow label="Stats">
          <Check
            toggle
            label="Enable In-Memory Stats"
            checked={f.enableInMemoryStats}
            onChange={(v) => set({ enableInMemoryStats: v })}
            help="This option will enable in-memory stats and only Last Hour data will be available on Dashboard. No stats data will be stored on disk."
          />
        </GroupRow>
        <TextRow
          label="Max Stat File Days"
          type="number"
          value={f.maxStatFileDays}
          onChange={(v) => set({ maxStatFileDays: v })}
          placeholder="Max Days"
          suffix="days (default 365, set 0 to disable auto delete)"
          help="Max number of days to keep the dashboard stats. Stat files older than the specified number of days will be deleted automatically."
        />
      </Block>
    </>
  )
}
