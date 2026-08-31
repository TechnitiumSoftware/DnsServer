import { Notices, Block, Check, GroupRow, Note, Plain, TextRow } from '../parts'
import type { PaneProps } from './tipos'

/* Settings > Cache (index.html:1911-2064). Cuatro bloques. */
export function Cache({ f, set, en }: PaneProps) {
  return (
    <>
      <Block title="DNS Cache">
        <GroupRow label="DNS Cache">
          <Check
            toggle
            label="Save Cache To Disk"
            checked={f.saveCache}
            onChange={(v) => set({ saveCache: v })}
            help="Enable this option to save DNS cache on disk when the DNS Server stops. The saved cache will be loaded next time the DNS Server starts."
          />
        </GroupRow>
        <Notices>
          <Note>
            The DNS Server will attempt to save cache to disk when it stops which may take time
            depending on the cache size. If the DNS Server takes a lot of time to stop then it may
            lead to the OS killing the DNS Server process causing an incomplete cache to be stored
            on disk.
          </Note>
        </Notices>
      </Block>

      <Block title="Serve Stale">
        <GroupRow label="Serve Stale">
          <Check
            toggle
            label="Enable Serve Stale"
            checked={f.serveStale}
            onChange={(v) => set({ serveStale: v })}
            help={
              <>
                Enable the{' '}
                <a href="https://datatracker.ietf.org/doc/rfc8767/" target="_blank" rel="noreferrer">
                  Serve Stale
                </a>{' '}
                feature to improve resiliency by using expired or stale records in cache to respond
                when the DNS Server is unable to reach the upstream or authoritative name servers to
                refresh the expired records before the Max Wait Time configured below.
              </>
            }
          />
        </GroupRow>
        <TextRow
          label="Serve Stale TTL"
          value={f.serveStaleTtl}
          onChange={(v) => set({ serveStaleTtl: v })}
          placeholder="seconds"
          suffix="seconds (recommended 259200/3d)"
          disabled={!en.serveStale}
          help="The TTL value in seconds which should be used for cached records that are expired. When the serve stale TTL too expires for a stale record, it gets removed from the cache. Recommended value is between 1-3 days and maximum supported value is 7 days."
        />
        <TextRow
          label="Serve Stale Answer TTL"
          value={f.serveStaleAnswerTtl}
          onChange={(v) => set({ serveStaleAnswerTtl: v })}
          placeholder="seconds"
          suffix="seconds (valid range 0-300/5m; recommended 30)"
          disabled={!en.serveStale}
          help="The TTL value in seconds which should be used for the records in a stale response. This is the TTL value that the client will be using to cache the stale records."
        />
        <TextRow
          label="Serve Stale Reset TTL"
          value={f.serveStaleResetTtl}
          onChange={(v) => set({ serveStaleResetTtl: v })}
          placeholder="seconds"
          suffix="seconds (valid range 10-900/15m; recommended 30)"
          disabled={!en.serveStale}
          help="The TTL value in seconds which should be used to reset the stale record's TTL value in the cache when the resolver fails to refresh the data. The TTL reset causes the stale records to become valid again so that they can be used to serve requests normally. This reset effectively prevents the resolver from attempting to frequently update the stale records."
        />
        <TextRow
          label="Serve Stale Max Wait Time"
          type="number"
          value={f.serveStaleMaxWaitTime}
          onChange={(v) => set({ serveStaleMaxWaitTime: v })}
          placeholder="milliseconds"
          suffix="milliseconds (valid range 0-1800; default 1800)"
          disabled={!en.serveStale}
          help="The time in milliseconds that the DNS Server must wait for the resolver before serving stale records from the cache. Lower value will ensure faster response at the expense of not getting updated data from the upstream. Setting value to 0 will instantly return stale answer without waiting for the resolver to fetch updates from the upstream."
        />
      </Block>

      <Block title="Cache Limits">
        <TextRow
          label="Cache Maximum Entries"
          type="number"
          value={f.cacheMaximumEntries}
          onChange={(v) => set({ cacheMaximumEntries: v })}
          placeholder="entries"
          width={125}
          suffix="(default 10000; set 0 for unlimited entries)"
          help="The maximum number of entries that the cache can store. A relevant value should be configured by monitoring the Cache entries value on Dashboard and the server's memory usage to limit the amount of RAM used by the DNS Server. A cache entry is a complete Resource Record Set (RR Set) which is a group of records with the same type for a given domain name. When a value is configured, the DNS Server will trigger a clean up operation every few minutes and remove least recently used entries to maintain the maximum allowed entries in cache."
        />
        <TextRow
          label="Cache Minimum TTL"
          value={f.cacheMinimumRecordTtl}
          onChange={(v) => set({ cacheMinimumRecordTtl: v })}
          placeholder="min TTL"
          suffix="seconds (recommended 10)"
          help="The minimum TTL value that a record can have in the cache. Set a value to make sure that the records with TTL value less than that stays in cache for a minimum duration."
        />
        <TextRow
          label="Cache Maximum TTL"
          value={f.cacheMaximumRecordTtl}
          onChange={(v) => set({ cacheMaximumRecordTtl: v })}
          placeholder="max TTL"
          suffix="seconds (default 604800/1w)"
          help="The maximum TTL value that a record can have in the cache. Set a lower value to allow the records to expire early."
        />
        <TextRow
          label="Cache Negative TTL"
          value={f.cacheNegativeRecordTtl}
          onChange={(v) => set({ cacheNegativeRecordTtl: v })}
          placeholder="-ve TTL"
          suffix="seconds (recommended 300/5m)"
          help={
            <>
              The negative TTL value to use when there is no SOA MINIMUM value available. Negative
              caching stores records in cache for <code>NXDOMAIN</code> and <code>NODATA</code>{' '}
              responses.
            </>
          }
        />
        <TextRow
          label="Cache Failure TTL"
          value={f.cacheFailureRecordTtl}
          onChange={(v) => set({ cacheFailureRecordTtl: v })}
          placeholder="fail TTL"
          suffix="seconds (recommended 10)"
          help={
            <>
              The failure TTL value to be used for caching failure responses. This allows storing
              failure record in cache and prevent frequent recursive resolution requests to the name
              servers that are responding with <code>ServerFailure</code> or failing to respond.
            </>
          }
        />
      </Block>

      <Block title="Prefetch">
        <TextRow
          label="Prefetch Eligibility"
          type="number"
          value={f.cachePrefetchEligibility}
          onChange={(v) => set({ cachePrefetchEligibility: v })}
          placeholder="eligibility"
          suffix="seconds (recommended 2)"
          help="The minimum initial TTL value of a record needed to be eligible for prefetching."
        />
        <TextRow
          label="Prefetch Trigger"
          type="number"
          value={f.cachePrefetchTrigger}
          onChange={(v) => set({ cachePrefetchTrigger: v })}
          placeholder="trigger"
          suffix="seconds (recommended 9; set 0 to disable prefetching & auto prefetching)"
          help="A record with TTL value less than trigger value will initiate prefetch operation immediately for itself."
        />
        <TextRow
          label="Auto Prefetch Sampling"
          type="number"
          value={f.cachePrefetchSampleIntervalInMinutes}
          onChange={(v) => set({ cachePrefetchSampleIntervalInMinutes: v })}
          placeholder="interval"
          suffix="minutes (valid range 1-60; default 5)"
          help="The interval to sample eligible domain names from last hour stats for auto prefetch."
        />
        <TextRow
          label="Auto Prefetch Eligibility"
          type="number"
          value={f.cachePrefetchSampleEligibilityHitsPerHour}
          onChange={(v) => set({ cachePrefetchSampleEligibilityHitsPerHour: v })}
          placeholder="hits"
          suffix="hits/hour (default 30)"
          help="Minimum required hits per hour for a domain name to be eligible for auto prefetch."
        />
        <Plain>
          The DNS Server cache auto prefetch option can keep eligible domain names from last hour
          stats "hot" in cache. Auto prefetch eligibility value can be decided by keeping an eye on
          the hits shown for last hour on the dashboard. Experiment with auto prefetch sampling
          interval and eligibility to get best results.
        </Plain>
      </Block>
    </>
  )
}
