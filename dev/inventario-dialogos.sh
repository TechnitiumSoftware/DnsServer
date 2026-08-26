#!/usr/bin/env bash
# Regenera el inventario de diálogos de la consola nueva. Las cifras del plan de
# revisión salen de aquí, no de la memoria de nadie.
#
#   dev/inventario-dialogos.sh          tabla por fichero
#   dev/inventario-dialogos.sh titulos  además, el título de cada diálogo
set -euo pipefail
cd "$(dirname "$0")/../DnsServerCore/webapp/src"

tot_d=0; tot_c=0
printf '%-3s %-3s  %s\n' D C FICHERO
while read -r f; do
  d=$(grep -c '<Dialog' "$f" || true)
  c=$(grep -c '<Confirm' "$f" || true)
  tot_d=$((tot_d + d)); tot_c=$((tot_c + c))
  printf '%-3s %-3s  %s\n' "$d" "$c" "${f#./}"
  if [ "${1:-}" = titulos ]; then
    grep -o 'title={\?[^}]*}\?' "$f" | grep -v '<Alert' | sed 's/^/       /' || true
  fi
done < <(grep -rl '<Dialog\|<Confirm' --include='*.tsx' --exclude='*test*' . | sort)

echo
echo "Diálogos (<Dialog>): $tot_d en $(grep -rl '<Dialog' --include='*.tsx' --exclude='*test*' . | wc -l) ficheros"
echo "Confirmaciones (<Confirm>): $tot_c en $(grep -rl '<Confirm' --include='*.tsx' --exclude='*test*' . | wc -l) ficheros"
