#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for help-steps/variables CONFIGURATION PRECEDENCE.
##
## The model is the plain guard idiom (set_default_variable = set-if-unset),
## sourced highest-priority-first: parse-cmd (CLI) sets passed options
## UNCONDITIONALLY first, the environment is already present, and everything
## after fills only what is still unset. So, with no gymnastics:
##
##   command-line  >  environment  >  config-file (set_default_variable)  >  default
##
## A config file participates in the ladder by using 'set_default_variable NAME
## value' (fill-if-empty): it OVERRIDES a built-in code default (the user config
## tiers are sourced in 10_core.bsh BEFORE the defaults), yet still RESPECTS an
## env value or a --CLI flag (both already set by then, so fill-if-empty skips).
## A bare 'NAME=value' in a config file is a deliberate FORCED OVERRIDE (the
## documented power-user escape hatch) and wins over everything -- that is the
## meaning of an unconditional assignment, not a bug.
##
## Verified on a representative input, 'dist_build_hostname' (CLI '--hostname',
## env 'dist_build_hostname', default 'localhost'), by resolving the REAL
## pre+variables under each layer combination. No network, no build; needs root /
## dist_build_allow_root=true (the suite elevates) because sourcing variables
## shells out to sudo.

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

## Two config files: one that participates in the ladder (set_default_variable)
## and one that forces (bare assignment).
conf_sdv="$(mktemp --suffix=.conf)"
conf_force="$(mktemp --suffix=.conf)"
# shellcheck disable=SC2317  # reached via the EXIT trap
cleanup() {
   safe-rm --force -- "${conf_sdv}" "${conf_force}"
}
trap cleanup EXIT
printf '%s\n' 'set_default_variable dist_build_hostname CONFVAL' > "${conf_sdv}"
printf '%s\n' 'dist_build_hostname=CONFVAL' > "${conf_force}"

base_args=( --flavor kicksecure-cli --type vm --target raw --freshness current --arch amd64 --freedom false )

## Resolve dist_build_hostname under one layer combination.
##   $1 description  $2 expected  $3 env assignment ('' none)  rest = extra args
resolve_check() {
   local desc="$1" expected="$2" envassign="$3"
   shift 3
   local got
   # shellcheck disable=SC2086  # envassign is controlled test input, split intentionally
   got="$(
      cd -- "${dm_checkout}" \
         && env dist_build_allow_root=true dist_build_unlock_dangerous_options=true ${envassign} \
            bash "${inner}" dist_build_hostname "${base_args[@]}" "$@" 2>&2 \
         | grep '^RESULT=' | head -1 | cut -d= -f2-
   )" || true
   if [ "${got}" = "${expected}" ]; then
      pass "${desc}: dist_build_hostname='${got}'"
   else
      fail "${desc}: expected '${expected}', got '${got}'"
   fi
}

## --- the ladder: CLI > env > default ---------------------------------------
resolve_check "default (nothing set)" localhost ""                          --
resolve_check "env beats default"     ENVVAL    "dist_build_hostname=ENVVAL" --
resolve_check "CLI beats default"     CLIVAL    ""                          --hostname CLIVAL
resolve_check "CLI beats env"         CLIVAL    "dist_build_hostname=ENVVAL" --hostname CLIVAL

## --- a config file using set_default_variable OVERRIDES a code default -------
resolve_check "config(set_default_variable) beats default" CONFVAL "" --conffile "${conf_sdv}"

## --- ... but still RESPECTS env and CLI --------------------------------------
resolve_check "config(set_default_variable) yields to CLI" CLIVAL "" --hostname CLIVAL --conffile "${conf_sdv}"
resolve_check "config(set_default_variable) yields to env" ENVVAL "dist_build_hostname=ENVVAL" --conffile "${conf_sdv}"

## --- a bare assignment in a config file is a FORCED override ----------------
resolve_check "config(bare =) forces over default" CONFVAL "" --conffile "${conf_force}"
resolve_check "config(bare =) forces over CLI"     CONFVAL "" --hostname CLIVAL --conffile "${conf_force}"

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: config precedence (CLI > env > set_default_variable config > default; bare = forces)."
