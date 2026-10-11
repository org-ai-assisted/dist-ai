#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## vbox-disk-extract runs as root and reads --passphrase-file into memory. A LUKS key
## is tiny, so luks_open caps the read (head --bytes): a file mispointed at an endless
## device (/dev/zero, /dev/urandom) cannot spin or OOM the root process. Sources the
## real vbox-disk-extract, drives luks_open with an oversized file and a recording
## cryptsetup stub, and asserts the delivered key is bounded below the file's size --
## the same cap that stops the endless-device spin. Canaried against the pre-cap
## "$(< file)" form, which hands cryptsetup the whole file.

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

work="$(mktemp --directory --tmpdir passphrase-bounded-test.XXXXXX)"
passphrase_bounded_cleanup() {
   safe-rm --recursive --force -- "${work}"
}
trap passphrase_bounded_cleanup EXIT

failures=0
check() {
   if [ "$2" = 'true' ]; then
      printf '%s\n' "ok: $1"
   else
      printf '%s\n' "FAIL: $1" >&2
      failures=$((failures + 1))
   fi
}

## Recording cryptsetup stub: capture the key bytes luks_open hands it on stdin.
key_seen="${work}/key-seen"
cryptsetup() {
   cat > "${key_seen}"
}

## A 4 MiB passphrase file of non-NUL bytes, far above the cap: the capped read hands
## cryptsetup fewer bytes than the file holds; the uncapped form would hand it all.
# shellcheck disable=SC2034  # read by the sourced luks_open
passphrase_file="${work}/big-pass"
input_bytes=$((4 * 1024 * 1024))
head -c "${input_bytes}" /dev/zero | tr '\0' 'x' > "${passphrase_file}"

luks_open /dev/nbd-test vde-test-luks
seen_bytes="$(wc -c < "${key_seen}")"
check "the oversized passphrase file is read bounded below its size" \
   "$([ "${seen_bytes}" -gt 0 ] && [ "${seen_bytes}" -lt "${input_bytes}" ] && printf '%s' 'true' || printf '%s' 'false')"

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "${failures} passphrase-bounded assertion(s) failed" >&2
   exit 1
fi
printf '%s\n' 'all passphrase-bounded assertions passed'
