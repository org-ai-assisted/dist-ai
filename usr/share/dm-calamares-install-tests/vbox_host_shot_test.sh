#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Unit test for vbox-host-shot's pure helpers, sourced from the real script (the source guard
## keeps main() -- the compositor/Manager/grim pipeline -- from running). Covers:
##  - vm_uuid: extracts the UUID from VBoxManage showvminfo --machinereadable; empty on a miss
##    or an empty name (so the Manager just opens with no pre-selection).
##  - parse_args: fills the option vars, REQUIRES --out, and rejects an unknown flag (exit 2).
## The capture path itself (Wayland socket discovery, trap teardown, grim) is e2e-only.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
subject=""
for candidate in "${VBOX_HOST_SHOT:-}" \
   "${test_dir}/../../bin/vbox-host-shot" \
   "/usr/bin/vbox-host-shot"; do
   [ -n "${candidate}" ] || continue
   if [ -x "${candidate}" ]; then
      subject="$(readlink --canonicalize -- "${candidate}")"
      break
   fi
done
[ -n "${subject}" ] || { printf '%s\n' "FATAL: vbox-host-shot not found (set VBOX_HOST_SHOT)." >&2; exit 1; }

pass=0
fail=0
check() {
   if [ "$2" -eq 0 ]; then
      pass=$(( pass + 1 ))
      printf '%s\n' "PASS: $1"
   else
      fail=$(( fail + 1 ))
      printf '%s\n' "FAIL: $1"
   fi
}
ok() {
   if [ "$1" = "$2" ]; then
      printf '%s\n' 0
   else
      printf '%s\n' 1
   fi
}

## Stub: 'showvminfo <name> --machinereadable' prints a canned block for the known VM, rc 1 for
## anything else -- exactly the surface vm_uuid parses. Defined before sourcing so vm_uuid binds it.
# shellcheck disable=SC2317  ## reached only through the sourced ${VBOXMANAGE}, not a literal call
VBoxManage() {
   case "$1" in
      showvminfo)
         case "$2" in
            knownvm)
               printf '%s\n' 'name="knownvm"' \
                  'UUID="5bfdfe22-933f-4875-a6a9-2b9ec88104c5"' 'ostype="Debian_64"'
               ;;
            *)
               return 1
               ;;
         esac
         ;;
      *)
         return 1
         ;;
   esac
}

# shellcheck disable=SC1090  ## the real script is resolved at runtime; ${VBOXMANAGE} defaults to it
source "${subject}"

## vm_uuid: known VM -> its UUID; unknown or empty -> empty string.
got="$(vm_uuid knownvm)" || true
check "vm_uuid extracts UUID for a known VM" "$(ok "${got}" "5bfdfe22-933f-4875-a6a9-2b9ec88104c5")"
got="$(vm_uuid nosuchvm)" || true
check "vm_uuid is empty for an unknown VM" "$(ok "${got}" "")"
got="$(vm_uuid "")" || true
check "vm_uuid is empty for an empty name" "$(ok "${got}" "")"

## parse_args: --out is required (clean state first, since a later case mutates the globals).
out=""
rc=0
( parse_args --vm foo ) || rc=$?
check "parse_args requires --out (exit 2)" "$(ok "${rc}" 2)"

rc=0
( parse_args --out dummy.png --bogus ) || rc=$?
check "parse_args rejects an unknown flag (exit 2)" "$(ok "${rc}" 2)"

## parse_args fills the option vars (runs in the current shell on purpose). Seed the names first
## so this file reads as assigning them (the sourced subject also declares them).
vm=""
width=""
height=""
parse_args --vm myvm --out dummy.png --width 800 --height 600
check "parse_args sets vm" "$(ok "${vm}" myvm)"
check "parse_args sets out" "$(ok "${out}" dummy.png)"
check "parse_args sets width" "$(ok "${width}" 800)"
check "parse_args sets height" "$(ok "${height}" 600)"

printf '%s\n' "" "vbox_host_shot_test: ${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1
exit 0
