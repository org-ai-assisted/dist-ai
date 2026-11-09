#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The --vm name is used as a path component under the VBox machine folder, including a
## `safe-rm --recursive` of a stale per-VM dir in build_vm. A name containing '/' or '..' would
## traverse out of that per-VM scope, so main() rejects it up front (SETUP_RC). Drives the REAL
## dm-calamares-install with a traversing --vm (the guard fires before any root/VBox step).
## [CANARY: pre-fix there is no guard, so this specific rejection message is absent.]

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
subject=""
for candidate in "${DM_CALAMARES_INSTALL:-}" \
   "${test_dir}/../../bin/dm-calamares-install" \
   "/usr/bin/dm-calamares-install"; do
   [ -n "${candidate}" ] || continue
   if [ -x "${candidate}" ]; then
      subject="$(readlink --canonicalize -- "${candidate}")"
      break
   fi
done
[ -n "${subject}" ] || { printf '%s\n' "FATAL: dm-calamares-install not found (set DM_CALAMARES_INSTALL)." >&2; exit 1; }

pass=0
fail=0
check() {
   if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: ${1}"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: ${1}"; fi
}
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac }

## A '..'-traversing name is rejected at SETUP_RC with the guard message (fires before --iso /
## --passphrase-file are needed, so no other required-arg error pre-empts it).
rc=0
err="$("${subject}" --vm '../../tmp/victim' </dev/null 2>&1)" || rc=$?
got=0; [ "${rc}" -eq 2 ] || got=1
check "traversing --vm exits SETUP_RC (2)" "${got}"
got=0; has "must not contain '/' or '..'" "${err}" || got=1
check "traversing --vm rejected by the name guard" "${got}"

## A '/'-bearing name is likewise rejected.
rc=0
err="$("${subject}" --vm 'a/b' </dev/null 2>&1)" || rc=$?
got=0; has "must not contain '/' or '..'" "${err}" || got=1
check "slash-bearing --vm rejected by the name guard" "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
