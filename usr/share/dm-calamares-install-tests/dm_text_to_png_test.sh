#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-text-to-png renders stdin into a real PNG state card (used by dm-calamares-install's
## story_card). Pins: a non-empty stdin yields a valid PNG; empty stdin is rejected (a blank
## card is never silently produced). Drives the REAL tool. ImageMagick is a hard dependency
## (a missing 'convert'/'magick' is an environment bug, surfaced -- never a silent skip).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
subject=""
for candidate in "${DM_TEXT_TO_PNG:-}" \
   "${test_dir}/../../bin/dm-text-to-png" \
   "/usr/bin/dm-text-to-png"; do
   [ -n "${candidate}" ] || continue
   if [ -x "${candidate}" ]; then
      subject="$(readlink --canonicalize -- "${candidate}")"
      break
   fi
done
[ -n "${subject}" ] || { printf '%s\n' "FATAL: dm-text-to-png not found (set DM_TEXT_TO_PNG)." >&2; exit 1; }

if ! type -P magick >/dev/null 2>&1 && ! type -P convert >/dev/null 2>&1; then
   printf '%s\n' "FATAL: ImageMagick ('magick'/'convert') not installed -- required, not skippable." >&2
   exit 1
fi

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

pass=0; fail=0
check() { if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; fi; }

## --- a non-empty card renders a valid PNG --------------------------------------------------
out="${work}/card.png"
printf '%s\n' '[state card -- rendered]' 'VMState="poweroff"' 'firmware="EFI"' | "${subject}" "${out}"
got=0; [ -s "${out}" ] || got=1
check "renders a non-empty file" "${got}"
## PNG magic: the first 8 bytes are \x89PNG\r\n\x1a\n.
got=0; case "$(head -c 4 -- "${out}" | od -An -tx1 | tr -d ' \n')" in 89504e47) ;; *) got=1 ;; esac
check "output is a real PNG (magic bytes)" "${got}"

## --- empty stdin is rejected (no blank card) -----------------------------------------------
rc=0
printf '%s' '' | "${subject}" "${work}/empty.png" >/dev/null 2>&1 || rc=$?
got=0; [ "${rc}" -ne 0 ] || got=1
check "empty stdin is rejected (non-zero)" "${got}"
got=0; [ ! -e "${work}/empty.png" ] || got=1
check "empty stdin writes no file" "${got}"

## --- missing OUTFILE arg is rejected -------------------------------------------------------
rc=0
printf '%s\n' x | "${subject}" >/dev/null 2>&1 || rc=$?
got=0; [ "${rc}" -ne 0 ] || got=1
check "missing OUTFILE is rejected" "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
