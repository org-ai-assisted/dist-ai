#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for help-steps/variables CONFIGURATION PRECEDENCE.
##
## The intended ladder (lowest -> highest):
##   code defaults  <  buildconfig.d / --conffile  <  environment  <  --CLI flag
##
## THE BUG IT GUARDS: buildconfig.d/--conffile is sourced AFTER parse-cmd (CLI)
## and after the code defaults, so an unconditional assignment in a config file
## ('dist_build_hostname=CONFVAL') used to OVERRIDE an explicit '--hostname' on
## the command line AND an environment value -- config wrongly beat the two
## layers that must outrank it. A caller who passed '--hostname foo' but also had
## any config file setting it got the config value, silently.
##
## Verifies the ladder on a representative user-overridable input,
## 'dist_build_hostname' (CLI '--hostname', env 'dist_build_hostname', default
## 'localhost'), by resolving the REAL pre+variables under each layer combination
## and checking the winner. No normalization needed (each resolve is its own
## process). No network, no build; needs root / dist_build_allow_root=true (the
## suite elevates) because sourcing variables shells out to sudo.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

if [ ! -r "${dm_checkout}/help-steps/variables" ]; then
   printf '%s\n' "FATAL: help-steps/variables not found at '${dm_checkout}' (set DERIVATIVE_MAKER_DIR)." >&2
   exit 1
fi

inner="${test_dir}/variables_precedence_inner.sh"
if [ ! -r "${inner}" ]; then
   printf '%s\n' "FATAL: inner runner not found at '${inner}'." >&2
   exit 1
fi

## A config file that sets the input UNCONDITIONALLY -- the realistic user
## --conffile / ~/buildconfig.d case, and the one that used to wrongly win.
conf_file="$(mktemp --suffix=.conf)"
# shellcheck disable=SC2317  # reached via the EXIT trap
cleanup() {
   safe-rm --force -- "${conf_file}"
}
trap cleanup EXIT
printf '%s\n' 'dist_build_hostname=CONFVAL' > "${conf_file}"

## Always-valid build command; --hostname / env / --conffile are layered on top.
base_args=( --flavor kicksecure-cli --type vm --target raw --freshness current --arch amd64 --freedom false )

## Resolve dist_build_hostname under one layer combination.
##   $1 = a description
##   $2 = the expected winner
##   $3 = env assignment string ('' for none; word-split on purpose, test input)
##   rest = extra build args (e.g. --hostname CLIVAL, --conffile ...)
resolve_check() {
   local desc="$1" expected="$2" envassign="$3"
   shift 3
   local got
   # shellcheck disable=SC2086  # envassign is controlled test input, split intentionally
   got="$(
      cd -- "${dm_checkout}" \
         && env dist_build_allow_root=true dist_build_unlock_dangerous_options=true ${envassign} \
            bash "${inner}" dist_build_hostname "${base_args[@]}" "$@" 2>/dev/null \
         | grep '^RESULT=' | head -1 | cut -d= -f2-
   )" || true
   if [ "${got}" = "${expected}" ]; then
      pass "${desc}: dist_build_hostname='${got}'"
   else
      fail "${desc}: expected '${expected}', got '${got}'"
   fi
}

## --- cases that already hold (the ladder for CLI/env/default) ----------------
resolve_check "default (nothing set)"      localhost ""                          --
resolve_check "env beats default"          ENVVAL    "dist_build_hostname=ENVVAL" --
resolve_check "CLI beats default"          CLIVAL    ""                          --hostname CLIVAL
resolve_check "CLI beats env"              CLIVAL    "dist_build_hostname=ENVVAL" --hostname CLIVAL
resolve_check "config beats default"       CONFVAL   ""                          --conffile "${conf_file}"

## --- the ladder rungs the fix restores (config must NOT outrank CLI/env) ------
resolve_check "CLI beats config"           CLIVAL    ""                          --hostname CLIVAL --conffile "${conf_file}"
resolve_check "env beats config"           ENVVAL    "dist_build_hostname=ENVVAL" --conffile "${conf_file}"

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: config precedence ladder (defaults < config < env < CLI) holds."
