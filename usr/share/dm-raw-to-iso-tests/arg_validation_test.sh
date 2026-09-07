#!/bin/bash

## Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drives the REAL dm-raw-to-iso with bad/missing arguments and asserts its exit
## codes and messages. Every case here is reached BEFORE the dependency check and
## before any privileged action, so this runs anywhere -- no root, no ISO tools,
## no image. It gates the argument-handling surface: remove a validation and a
## case flips from exit 1 to a later failure, and the assertion catches it.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

bin="${DM_RAW_TO_ISO_BIN:-/usr/bin/dm-raw-to-iso}"
[ -x "${bin}" ] || { printf 'FATAL: dm-raw-to-iso not executable: %s\n' "${bin}" >&2 ; exit 1 ; }

pass=0
fail=0

## A readable dummy file so '--raw <f>' passes the readability check and the case
## fails (or not) on the argument under test, not on a missing file.
tmp="$(mktemp --directory --tmpdir dm-raw-to-iso-argtest.XXXXXX)"
cleanup() {
   # shellcheck disable=SC2317  # reached only via the EXIT trap
   safe-rm --recursive --force -- "${tmp}" 2>/dev/null || true
}
trap cleanup EXIT
dummy_raw="${tmp}/raw.img"
printf '' > "${dummy_raw}"

## Run the tool, capture rc + output. Never let errexit abort the harness.
run() {
   captured_out=""
   captured_rc=0
   captured_out="$( "${bin}" "$@" 2>&1 )" || captured_rc=$?
}

## Assert an exact exit code.
expect_rc() {
   local want="$1" desc="$2"
   if [ "${captured_rc}" -eq "${want}" ]; then
      printf 'PASS: %s (rc=%s)\n' "${desc}" "${captured_rc}"
      pass=$(( pass + 1 ))
   else
      printf 'FAIL: %s: expected rc=%s, got rc=%s\n%s\n' "${desc}" "${want}" "${captured_rc}" "${captured_out}" >&2
      fail=$(( fail + 1 ))
   fi
}

## Assert the output contains a substring (message quality).
expect_msg() {
   local needle="$1" desc="$2"
   case "${captured_out}" in
      *"${needle}"*)
         printf 'PASS: %s (message contains "%s")\n' "${desc}" "${needle}"
         pass=$(( pass + 1 ))
         ;;
      *)
         printf 'FAIL: %s: message lacks "%s"\n%s\n' "${desc}" "${needle}" "${captured_out}" >&2
         fail=$(( fail + 1 ))
         ;;
   esac
}

## --help exits 0 and prints usage.
run --help
expect_rc 0 '--help exits 0'
expect_msg 'Usage:' '--help prints usage'

## No arguments -> missing --raw.
run
expect_rc 1 'no arguments fails'
expect_msg '--raw is required' 'no arguments names --raw'

## --raw without --output.
run --raw "${dummy_raw}"
expect_rc 1 '--raw without --output fails'
expect_msg '--output is required' 'missing --output named'

## Unreadable raw image.
run --raw "${tmp}/does-not-exist.img" --output "${tmp}/out.iso"
expect_rc 1 'unreadable raw fails'
expect_msg 'not readable' 'unreadable raw named'

## Unknown option.
run --raw "${dummy_raw}" --output "${tmp}/out.iso" --bogus
expect_rc 1 'unknown option fails'
expect_msg 'unknown argument' 'unknown option named'

## Option missing its value (last-token).
run --raw "${dummy_raw}" --output
expect_rc 1 '--output without value fails'
expect_msg '--output requires a value' 'missing value named'

## Unsupported architecture.
run --raw "${dummy_raw}" --output "${tmp}/out.iso" --arch sparc
expect_rc 1 'bad --arch fails'
expect_msg 'unsupported --arch' 'bad --arch named'

## Non-integer source-date-epoch.
run --raw "${dummy_raw}" --output "${tmp}/out.iso" --source-date-epoch notanumber
expect_rc 1 'non-integer --source-date-epoch fails'
expect_msg 'non-negative integer' 'bad --source-date-epoch named'

printf '\narg_validation: %s pass, %s fail\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ] || exit 1
[ "${pass}" -gt 0 ] || { printf 'FATAL: no assertions ran\n' >&2 ; exit 1 ; }
exit 0
