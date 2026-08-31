#!/usr/bin/env bash
# Regenerates the dialog inventory of the new console. The figures in the review
# plan come from here, not from anyone's memory.
#
#   dev/inventario-dialogos.sh          table per file
#   dev/inventario-dialogos.sh titulos  plus the title of each dialog
set -euo pipefail
cd "$(dirname "$0")/../DnsServerCore/webapp/src"

tot_d=0; tot_c=0
printf '%-3s %-3s  %s\n' D C FILE
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
echo "Dialogs (<Dialog>): $tot_d in $(grep -rl '<Dialog' --include='*.tsx' --exclude='*test*' . | wc -l) files"
echo "Confirmations (<Confirm>): $tot_c in $(grep -rl '<Confirm' --include='*.tsx' --exclude='*test*' . | wc -l) files"
