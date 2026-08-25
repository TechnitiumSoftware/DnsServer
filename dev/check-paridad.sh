#!/usr/bin/env bash
# Compara la consola de dev (5380) con la de referencia (5381).
# Uso: ./check-paridad.sh [ruta]   (por defecto: /)
#
# Compara CONTENIDO, no bytes: se normalizan los finales de línea antes de
# hashear. Hace falta porque el .gitattributes de upstream usa `* text=auto`,
# así que el repositorio guarda LF y el checkout convierte según la plataforma:
# nuestro árbol en Linux tiene LF, y la imagen oficial de Docker trae CRLF
# porque se construyó en Windows. Sin normalizar, dos ficheros idénticos
# saldrían distintos por 7.426 bytes de más (uno por línea, en el caso de
# index.html).
set -euo pipefail

RUTA="${1:-/}"
DEV="http://127.0.0.1:5380${RUTA}"
REF="http://127.0.0.1:5381${RUTA}"

for url in "$DEV" "$REF"; do
  if ! curl -sfo /dev/null "$url"; then
    echo "FALLO: $url no responde"
    exit 1
  fi
done

hash_normalizado() {
  curl -s "$1" | tr -d '\r' | sha256sum | cut -d' ' -f1
}

d=$(hash_normalizado "$DEV")
r=$(hash_normalizado "$REF")

echo "dev $d"
echo "ref $r"

if [ "$d" = "$r" ]; then
  echo "IDENTICOS"
  exit 0
else
  echo "DISTINTOS"
  exit 2
fi
