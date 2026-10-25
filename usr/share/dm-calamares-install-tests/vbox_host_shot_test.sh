#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Unit test for vbox-host-shot's pure helpers + verb dispatch, sourced from the real script (the
## source guard keeps the compositor/GUI/grim pipeline from running). Covers:
##  - vm_uuid: extracts the UUID from VBoxManage showvminfo --machinereadable; empty on a miss
##    or an empty name.
##  - parse_common_args: fills the option vars, REQUIRES --out, rejects an unknown flag (exit 2).
##  - verb dispatch: no subcommand and an unknown one FAIL (exit 2, no default); vm-window requires
##    --vm -- all three die before any compositor starts.
## The capture path itself (Wayland socket discovery, trap teardown, grim) is e2e-only.

## Option/state vars (vm/out/.../started_vm_uuid/supmsg_*) are READ by the sourced vbox-host-shot
## (parse_common_args / cleanup), not by this file -- shellcheck cannot see across the source and
## reports them "appears unused". File-wide SC2034 disable (before the first command so it is
## file-wide); the vars ARE consumed by the subject.
# shellcheck disable=SC2034

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

## parse_common_args: --out is required (clean state first, since a later case mutates the globals).
out=""
rc=0
( parse_common_args --vm foo ) || rc=$?
check "parse_common_args requires --out (exit 2)" "$(ok "${rc}" 2)"

rc=0
( parse_common_args --out dummy.png --bogus ) || rc=$?
check "parse_common_args rejects an unknown flag (exit 2)" "$(ok "${rc}" 2)"

## parse_common_args fills the option vars (runs in the current shell on purpose). Seed the names
## first so this file reads as assigning them (the sourced subject also declares them).
vm=""
width=""
height=""
parse_common_args --vm myvm --out dummy.png --width 800 --height 600
check "parse_common_args sets vm" "$(ok "${vm}" myvm)"
check "parse_common_args sets out" "$(ok "${out}" dummy.png)"
check "parse_common_args sets width" "$(ok "${width}" 800)"
check "parse_common_args sets height" "$(ok "${height}" 600)"

## Verb dispatch: no subcommand and an unknown subcommand both FAIL (exit 2) BEFORE any compositor
## or GUI is started (main dies in the dispatch case). No default verb (operator requirement).
rc=0
( main ) || rc=$?
check "main with no subcommand fails (exit 2, no default)" "$(ok "${rc}" 2)"
rc=0
( main bogus ) || rc=$?
check "main rejects an unknown subcommand (exit 2)" "$(ok "${rc}" 2)"

## vm-window REQUIRES --vm; it must die (exit 2) at that check, before starting the compositor.
vm=""
rc=0
( main vm-window --out dummy.png ) || rc=$?
check "vm-window requires --vm (exit 2, before compositor)" "$(ok "${rc}" 2)"

## vm-window with an UNREGISTERED VM must die 2 WITH the diagnostic -- not a bare, message-less
## errexit exit 1. vm_uuid ends in a pipeline whose VBoxManage stage exits nonzero for an unknown
## VM; the resolution needs '|| true' so the explicit [ -n uuid ] check can run. FAILS on pre-fix
## code: without the guard, errexit exits 1 before the die, so rc is 1 and no message is printed.
vm=""
rc=0
err="$( ( main vm-window --vm nosuchvm --out dummy.png ) 2>&1 1>/dev/null )" || rc=$?
check "vm-window unregistered VM dies 2 (not a bare exit 1)" "$(ok "${rc}" 2)"
got=1
case "${err}" in
   *"could not resolve a UUID"*)
      got=0
      ;;
esac
check "vm-window unregistered VM prints the diagnostic" "${got}"

## cleanup: a vm-window capture must leave no side effects -- the started VM is powered off CLEANLY
## (not a KILL abort) and the overridden global GUI/SuppressMessages is restored (coderabbit PR
## #751). Drive cleanup() directly with a recording VBoxManage stub. sleep is stubbed to a no-op so
## the trap's grace waits do not slow the suite.
# shellcheck disable=SC2317  ## reached via the sourced cleanup(), not a literal call
sleep() {
   return 0
}
vbox_calls="$(mktemp)"
export VBOX_CALLS="${vbox_calls}"
# shellcheck disable=SC2317  ## reached via the sourced ${VBOXMANAGE}, not a literal call
VBoxManage() {
   printf '%s\n' "$*" >> "${VBOX_CALLS}"
   return 0
}
## case A: SuppressMessages WAS set -> restored to the old value; the started VM is powered off.
## The pid/dir/log cleanup globals are already empty from the sourced subject, so cleanup acts
## only on what this case sets (the started VM + the saved SuppressMessages).
true > "${vbox_calls}"
started_vm_uuid="the-uuid"
supmsg_was_set="yes"
supmsg_saved="oldsup"
( cleanup ) >/dev/null 2>&1 || true
calls="$(cat "${vbox_calls}")"
got=1
case "${calls}" in
   *"controlvm the-uuid poweroff"*)
      got=0
      ;;
esac
check "cleanup powers off the started vm-window VM (clean, not a KILL abort)" "${got}"
got=1
case "${calls}" in
   *"setextradata global GUI/SuppressMessages oldsup"*)
      got=0
      ;;
esac
check "cleanup restores the overridden global GUI/SuppressMessages" "${got}"
## case B: SuppressMessages was ABSENT -> deleted (setextradata with no value); no VM to power off.
true > "${vbox_calls}"
started_vm_uuid=""
supmsg_was_set="no"
supmsg_saved=""
( cleanup ) >/dev/null 2>&1 || true
calls="$(cat "${vbox_calls}")"
got=1
case "${calls}" in
   *"setextradata global GUI/SuppressMessages"*)
      got=0
      ;;
esac
check "cleanup deletes GUI/SuppressMessages when it was absent" "${got}"

printf '%s\n' "" "vbox_host_shot_test: ${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1
exit 0
