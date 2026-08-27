#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression guards for a batch of input-handling hardening fixes. Structural
## (a full behavioural test would need mtools + a FAT image, a description-parser
## fixture, and a hostile HTTP server); each asserts the fixed FORM is still
## present, so a later "simplification" that reintroduces the bug is caught.
##   - dm-virtualbox-installer-exe-verify-windows: the CRL fetch (URL from the
##     UNTRUSTED installer signature) must cap size with --max-filesize.
##   - dm-normalize-fat-partition: the ESP re-image loops must be NUL-delimited
##     ('find -print0' + 'IFS= read -r -d ""') -- a name with a space or newline
##     must reach mmd/mcopy verbatim.
##   - dm-packaging-helper-script: the description-reading loop must be
##     'IFS= read' or leading whitespace (indentation, the ' .' paragraph break)
##     is stripped and misclassified.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi
dmf="${dm_checkout}/packages/kicksecure/developer-meta-files"
if [ ! -d "${dmf}/usr" ]; then
   printf '%s\n' "FATAL: developer-meta-files not found at '${dmf}' (set DERIVATIVE_MAKER_DIR)." >&2
   exit 1
fi

pass() {
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   printf '%s\n' "FAIL: $*" >&2
   test_failures=$((test_failures + 1))
}

## $1 file, $2 pattern (ERE), $3 label
assert_has() {
   if grep --quiet --extended-regexp -- "$2" "${dmf}/$1"; then
      pass "$3"
   else
      fail "$3 (pattern '$2' absent from $1)"
   fi
}
## $1 file, $2 pattern (ERE), $3 label
assert_absent() {
   if grep --quiet --extended-regexp -- "$2" "${dmf}/$1"; then
      fail "$3 (forbidden pattern '$2' present in $1)"
   else
      pass "$3"
   fi
}

verify=usr/bin/dm-virtualbox-installer-exe-verify-windows
assert_has "${verify}" 'curl .*--max-filesize' \
   "CRL fetch caps size with --max-filesize (untrusted URL, DoS)"

fat=usr/bin/dm-normalize-fat-partition
assert_has "${fat}" 'find .*-type d -print0' "FAT dir enumeration is NUL-delimited (-print0)"
assert_has "${fat}" 'find .*-type f -print0' "FAT file enumeration is NUL-delimited (-print0)"
assert_has "${fat}" "IFS= read -r -d ''" "FAT re-image loops read NUL records with IFS="
assert_absent "${fat}" 'while read -r (directory|file); do' \
   "no bare 'while read -r' over find output in the ESP re-image loops"

pkg=usr/bin/dm-packaging-helper-script
## Every description-text loop keeps leading whitespace. A bare 'while read -r
## line' (no IFS=) strips it; the word-splitting 'read -r first second _' is fine.
assert_absent "${pkg}" '^[[:space:]]*while read -r line; do' \
   "description loops use 'IFS= read -r line', not a whitespace-stripping bare read"

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: input hardening."
