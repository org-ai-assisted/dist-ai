#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## set_console_keymap must not attempt 'systemctl restart keyboard-setup.service'
## when not running as root. In practice the wrappers already gate root and the
## /etc/default/keyboard write fails first for non-root, so the guard is
## defense-in-depth that cannot be reached end to end without a contrived
## fakeroot. This is therefore a STRUCTURAL revert-guard, not a behavioural test:
## it asserts the guard is present in the shipped library and the resolved TODO
## is gone, so a silent revert of the fix fails the suite.
##
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v SET_KEYBOARD_LAYOUT_REPO ] || SET_KEYBOARD_LAYOUT_REPO=""

lib_rel='usr/libexec/helper-scripts/set-keyboard-layout.sh'
lib=""
if [ -n "${SET_KEYBOARD_LAYOUT_REPO}" ] && [ -r "${SET_KEYBOARD_LAYOUT_REPO}/${lib_rel}" ]; then
   lib="${SET_KEYBOARD_LAYOUT_REPO}/${lib_rel}"
elif [ -n "${HELPER_SCRIPTS_PATH:-}" ] && [ -r "${HELPER_SCRIPTS_PATH}/${lib_rel}" ]; then
   lib="${HELPER_SCRIPTS_PATH}/${lib_rel}"
elif [ -r "/${lib_rel}" ]; then
   lib="/${lib_rel}"
fi

if [ -z "${lib}" ]; then
   printf '%s\n' "FATAL: set-keyboard-layout.sh not found" >&2
   printf '%s\n' "set SET_KEYBOARD_LAYOUT_REPO or HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install the package" >&2
   exit 1
fi

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "  ok: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "  NOT OK: $1" >&2; }

## The console-restart block must be guarded by a root check.
if grep --quiet --fixed-strings -- '[ "$(id --user)" != 0 ]' "${lib}" \
   && grep --quiet --fixed-strings -- 'restart keyboard-setup.service' "${lib}"; then
   ok "root guard present in set_console_keymap"
else
   notok "root guard for the console-restart block is missing"
fi

## The resolved TODO must be gone (an addressed marker is deleted).
if grep --quiet --fixed-strings -- 'TODO: Do not try this if not running as root' "${lib}"; then
   notok "resolved TODO still present"
else
   ok "resolved TODO removed"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
