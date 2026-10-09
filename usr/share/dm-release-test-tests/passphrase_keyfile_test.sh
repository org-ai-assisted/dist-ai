#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The LUKS passphrase file is a text file (dm-release-test writes it with a trailing
## newline). dm-calamares-install types the passphrase without that newline, so
## vbox-disk-extract must hand cryptsetup the SAME bytes -- 'cryptsetup --key-file PATH'
## reads the file byte for byte, newline included, and the unlock fails ("No key
## available with this passphrase"). Sources the real vbox-disk-extract and drives
## luks_open with a cryptsetup stub that records the key bytes it receives on stdin.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

subject="${VBOX_DISK_EXTRACT_BIN:-}"
if [ -z "${subject}" ]; then
   if [ -f "${test_dir}/../../bin/vbox-disk-extract" ]; then
      subject="${test_dir}/../../bin/vbox-disk-extract"
   else
      subject='/usr/bin/vbox-disk-extract'
   fi
fi
[ -r "${subject}" ] || { printf '%s\n' "FATAL: vbox-disk-extract not found at ${subject}" >&2; exit 1; }
# shellcheck source=../../bin/vbox-disk-extract
source "${subject}"

work="$(mktemp --directory --tmpdir passphrase-keyfile-test.XXXXXX)"
passphrase_test_cleanup() {
   safe-rm --recursive --force -- "${work}"
}
trap passphrase_test_cleanup EXIT

failures=0
check() {
   if [ "$2" = 'true' ]; then
      printf '%s\n' "ok: $1"
   else
      printf '%s\n' "FAIL: $1" >&2
      failures=$((failures + 1))
   fi
}

## cryptsetup stub: records its argv and the key bytes on stdin when --key-file is '-'.
key_seen="${work}/key-seen"
args_seen="${work}/args-seen"
cryptsetup() {
   printf '%s\n' "$*" > "${args_seen}"
   cat > "${key_seen}"
}

## Exactly as dm-release-test writes it: printf '%s\n' "release-test-VERSION".
# shellcheck disable=SC2034  # read by the sourced luks_open
passphrase_file="${work}/pass"
printf '%s\n' 'release-test-18.2.3.5' > "${passphrase_file}"
printf '%s' 'release-test-18.2.3.5' > "${work}/want"

luks_open /dev/nbd-test vde-test-luks

check "cryptsetup reads the key from stdin" \
   "$(grep --quiet -- '--key-file - -- /dev/nbd-test vde-test-luks' "${args_seen}" && printf true || printf false)"
check "the key carries no trailing newline (matches the typed passphrase)" \
   "$(cmp --silent -- "${work}/want" "${key_seen}" && printf true || printf false)"

## An empty passphrase file is refused, never an empty key.
truncate --size=0 -- "${passphrase_file}"
empty_rc=0
( luks_open /dev/nbd-test vde-test-luks ) >/dev/null 2>&1 || empty_rc=$?
check "an empty passphrase file is refused" "$([ "${empty_rc}" -ne 0 ] && printf true || printf false)"

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "${failures} passphrase-keyfile assertion(s) failed" >&2
   exit 1
fi
printf '%s\n' 'all passphrase-keyfile assertions passed'
