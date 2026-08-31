import { apiRequest, type ApiOutcome } from './client'

/*
`api/dnsClient/resolve` (dnsclient.js:166). The same endpoint resolves and, with
`import=true`, also imports the resolved records into this server — which is why
the "Resolve" and "Import" buttons share a call.
*/

export const TYPES = ['A','NS','CNAME','SOA','PTR','MX','TXT','RP','AAAA','SRV','NAPTR','DNAME','DS','SSHFP','RRSIG','NSEC','DNSKEY','NSEC3','NSEC3PARAM','TLSA','ZONEMD','SVCB','HTTPS','URI','CAA','ANY','AXFR','ANAME'] as const
export const PROTOCOLS = ['UDP','TCP','TLS','HTTPS','QUIC'] as const

/*
Preparing the server before querying (dnsclient.js:99-119). Two things that are
not obvious and that get lost if they are not replicated:

  1. The field shows labels like "This Server {this-server}" and what gets sent is
     ONLY what sits between the first "{" and the last "}".
  2. If the server is `recursive-resolver` or `system-dns`, the protocol is
     FORCED to UDP, however much the dropdown says otherwise.

And the empty-server warning is checked AFTER extracting, not before: a label
like "{}" is an empty server even though the field has text.
*/
export function prepararServidor(
  server: string,
  protocol: string,
): { server: string; protocol: string } {
  const forceUdp = server.includes('recursive-resolver') || server.includes('system-dns')

  let s = server
  const i = s.indexOf('{')
  if (i > -1) {
    const j = s.lastIndexOf('}')
    s = s.substring(i + 1, j)
  }

  return { server: s.trim(), protocol: forceUdp ? 'UDP' : protocol }
}

export interface ResolveParams {
  server: string
  domain: string
  type: string
  protocol: string
  dnssec: boolean
  eDnsClientSubnet?: string
  runImport?: boolean
}

export interface ResolveResult {
  result: unknown
  rawResponses?: string[]
  warningMessage?: string
}

export function resolve(
  token: string | null,
  p: ResolveParams,
): Promise<ApiOutcome<{ response: ResolveResult }>> {
  const body: Record<string, string> = {
    server: p.server,
    domain: p.domain,
    type: p.type,
    protocol: p.protocol,
    dnssec: String(p.dnssec),
    eDnsClientSubnet: p.eDnsClientSubnet ?? '',
  }
  if (p.runImport) body.import = 'true'
  return apiRequest<{ response: ResolveResult }>('dnsClient/resolve', { token, body })
}
