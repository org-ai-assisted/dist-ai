#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## get_colors.sh forces color output (bypassing the 'stderr is a TTY' check) when
## COLOR_FORCE_YES=true. This is the renamed successor of ASSUME_TERM_PRESENT; the
## old name must no longer have any effect.
##
## Sources the REAL get_colors.sh with a non-TTY stderr (redirected to /dev/null)
## so only the force variable can turn color on. Drives it under three envs:
## COLOR_FORCE_YES=true (color on), ASSUME_TERM_PRESENT=true (must be inert now),
## and neither (color off). No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   repo="${HELPER_SCRIPTS_REPO}"
else
   repo=""
fi

get_colors_sh="${repo:-}/usr/libexec/helper-scripts/get_colors.sh"
[ -r "${get_colors_sh}" ] || get_colors_sh='/usr/libexec/helper-scripts/get_colors.sh'

if [ ! -r "${get_colors_sh}" ]; then
   printf '%s\n' "FATAL: get_colors.sh not readable at '${get_colors_sh}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a checkout, or install helper-scripts" >&2
   exit 1
fi

## HELPER_SCRIPTS_PATH lets get_colors.sh resolve its own sibling
## (check_runtime.bsh); default to the same checkout the subject came from.
helper_scripts_path="${HELPER_SCRIPTS_PATH:-${repo}}"

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "  ok: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "  NOT OK: $1" >&2; }

## Source get_colors.sh with the given env and a non-TTY stderr, then print the
## resulting ${red}. Non-empty means color was turned on. Runs in a child bash so
## each case is isolated; stderr -> /dev/null makes 'test -t 2' false.
red_after_get_colors() {
   env "$@" \
      HELPER_SCRIPTS_PATH="${helper_scripts_path}" \
      TERM='xterm-256color' NO_COLOR='' ANSI_COLORS_DISABLED='' \
      /usr/bin/bash -c '
         source "${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/get_colors.sh"
         printf "%s" "${red:-}"
      ' 2>/dev/null
}

if [ -n "$(red_after_get_colors COLOR_FORCE_YES=true)" ]; then
   ok "COLOR_FORCE_YES=true forces color (red is set)"
else
   notok "COLOR_FORCE_YES=true did not force color"
fi

if [ -z "$(red_after_get_colors ASSUME_TERM_PRESENT=true)" ]; then
   ok "ASSUME_TERM_PRESENT=true is inert (old name no longer forces color)"
else
   notok "ASSUME_TERM_PRESENT=true still forced color: the old name was not removed"
fi

if [ -z "$(red_after_get_colors COLOR_FORCE_YES=false)" ]; then
   ok "no force + non-TTY: color off"
else
   notok "expected color off without a force variable on a non-TTY"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
