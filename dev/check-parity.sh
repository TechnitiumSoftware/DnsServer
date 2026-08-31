#!/usr/bin/env bash
# Compares the dev console (5380) against the reference one (5381).
# Usage: ./check-parity.sh [path]   (default: /)
#
# It compares CONTENT, not bytes: line endings are normalised before hashing.
# This is needed because upstream's .gitattributes uses `* text=auto`, so the
# repository stores LF and the checkout converts according to the platform: our
# tree on Linux has LF, and the official Docker image ships CRLF because it was
# built on Windows. Without normalising, two identical files would come out
# different by 7,426 extra bytes (one per line, in the case of index.html).
set -euo pipefail

PATH_="${1:-/}"
DEV="http://127.0.0.1:5380${PATH_}"
REF="http://127.0.0.1:5381${PATH_}"

for url in "$DEV" "$REF"; do
  if ! curl -sfo /dev/null "$url"; then
    echo "FAILED: $url does not answer"
    exit 1
  fi
done

normalised_hash() {
  curl -s "$1" | tr -d '\r' | sha256sum | cut -d' ' -f1
}

d=$(normalised_hash "$DEV")
r=$(normalised_hash "$REF")

echo "dev $d"
echo "ref $r"

if [ "$d" = "$r" ]; then
  echo "IDENTICAL"
  exit 0
else
  echo "DIFFERENT"
  exit 2
fi
