#!/usr/bin/env bash
# El servidor honra X-Forwarded-Prefix y monta un PathBase
# (DnsWebService.cs:1943-1945). Esta comprobación simula ese proxy y verifica
# que el bundle se pide en relativo, no en absoluto.
set -euo pipefail

PREFIJO="/dns"
BASE="http://127.0.0.1:5380"

html=$(curl -s -H "X-Forwarded-Prefix: ${PREFIJO}" -H "X-Forwarded-Proto: https" "${BASE}/")

rutas=$(echo "$html" | grep -oE '(src|href)="[^"]+"' | sed -E 's/^(src|href)="//; s/"$//')

echo "Rutas emitidas:"
echo "$rutas" | sed 's/^/  /'

if echo "$rutas" | grep -q '^/'; then
  echo "FALLO: hay rutas absolutas. Con un proxy en ${PREFIJO} el navegador las pediría fuera del prefijo y darían 404."
  exit 1
fi

echo "OK: todas las rutas son relativas; sobreviven a un proxy con prefijo."
