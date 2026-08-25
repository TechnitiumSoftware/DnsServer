import { apiRequest, type ApiOutcome } from './client'

/*
`api/dnsClient/resolve` (dnsclient.js:166). El mismo endpoint resuelve y, con
`import=true`, además importa los registros resueltos a este servidor — por eso
los botones «Resolve» e «Import» comparten llamada.
*/

export const TIPOS = ['A','NS','CNAME','SOA','PTR','MX','TXT','RP','AAAA','SRV','NAPTR','DNAME','DS','SSHFP','RRSIG','NSEC','DNSKEY','NSEC3','NSEC3PARAM','TLSA','ZONEMD','SVCB','HTTPS','URI','CAA','ANY','AXFR','ANAME'] as const
export const PROTOCOLOS = ['UDP','TCP','TLS','HTTPS','QUIC'] as const

/*
Preparación del servidor antes de consultar (dnsclient.js:99-119). Dos cosas que
no son obvias y que se pierden si no se replican:

  1. El campo muestra etiquetas como «This Server {this-server}» y lo que se
     envía es SÓLO lo que hay entre la primera «{» y la última «}».
  2. Si el servidor es `recursive-resolver` o `system-dns`, el protocolo se
     FUERZA a UDP, aunque el desplegable diga otra cosa.

Y el aviso de servidor vacío se comprueba DESPUÉS de extraer, no antes: una
etiqueta como «{}» es un servidor vacío aunque el campo tenga texto.
*/
export function prepararServidor(
  server: string,
  protocol: string,
): { server: string; protocol: string } {
  const forzarUdp = server.includes('recursive-resolver') || server.includes('system-dns')

  let s = server
  const i = s.indexOf('{')
  if (i > -1) {
    const j = s.lastIndexOf('}')
    s = s.substring(i + 1, j)
  }

  return { server: s.trim(), protocol: forzarUdp ? 'UDP' : protocol }
}

export interface ResolveParams {
  server: string
  domain: string
  type: string
  protocol: string
  dnssec: boolean
  eDnsClientSubnet?: string
  importar?: boolean
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
  if (p.importar) body.import = 'true'
  return apiRequest<{ response: ResolveResult }>('dnsClient/resolve', { token, body })
}
