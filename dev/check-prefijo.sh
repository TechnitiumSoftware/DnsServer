#!/usr/bin/env bash
# The server honours X-Forwarded-Prefix and mounts a PathBase
# (DnsWebService.cs:1943-1945). This check simulates that proxy and verifies the
# bundle is requested relatively, not absolutely.
set -euo pipefail

PREFIX="/dns"
BASE="http://127.0.0.1:5380"

html=$(curl -s -H "X-Forwarded-Prefix: ${PREFIX}" -H "X-Forwarded-Proto: https" "${BASE}/")

paths=$(echo "$html" | grep -oE '(src|href)="[^"]+"' | sed -E 's/^(src|href)="//; s/"$//')

echo "Emitted paths:"
echo "$paths" | sed 's/^/  /'

if echo "$paths" | grep -q '^/'; then
  echo "FAILED: there are absolute paths. Behind a proxy at ${PREFIX} the browser would request them outside the prefix and they would 404."
  exit 1
fi

echo "OK: every path is relative; they survive a prefixed proxy."
