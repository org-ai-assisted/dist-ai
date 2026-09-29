#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## derivative-update's remote fetch is MANDATORY and UNCONDITIONAL. The script's
## sole purpose is to fetch NEW code from the network and verify its authenticity,
## so the bulk
##     git fetch --recurse-submodules --jobs=100 || error 'Failed to fetch ...'
## must run on every invocation -- it must NOT be skipped in --update-only mode or
## otherwise wrapped in an update_only conditional. This is a deliberate maintainer
## decision (see the note above the fetch in derivative-update); this guard exists
## so an AI does not re-introduce an offline/update-only fetch skip.
##
## This is a SOURCE guard: the end-to-end path first runs git_sanity_test, which
## needs real OpenPGP-signed commits + keys, so it cannot be fixtured cheaply here
## -- it is exercised by the green CI dry-run lane.

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

## derivative-update is a top-level script of the derivative-maker checkout (a
## sibling of help-steps/), not itself under help-steps/.
subject=""
for candidate in "${DERIVATIVE_UPDATE:-}" \
   "${DERIVATIVE_MAKER_DIR:-}/derivative-update" \
   "${dm_checkout}/derivative-update"; do
   case "${candidate}" in
      ''|'/derivative-update')
         continue
         ;;
   esac
   if [ -r "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: derivative-update not found (set DERIVATIVE_UPDATE)." >&2
   exit 1
fi

## Line number of the remote fetch.
fetch_line="$( grep -nE 'git fetch --recurse-submodules' -- "${subject}" | head -1 | cut -d: -f1 )"
if [ -z "${fetch_line}" ]; then
   fail "no 'git fetch --recurse-submodules' in ${subject}; the fetch moved -- update this test"
else
   ## The lines immediately above the fetch must NOT re-wrap it in an update_only
   ## skip (an 'else' branch, or an 'if update_only != true'). A re-guarded fetch
   ## would place one of these directly above it; the mandatory fetch has only its
   ## explanatory comment there. (Kept to a tight window so the unrelated
   ## update_only target_tag block further above is not misread as a guard.)
   window_start=$(( fetch_line > 6 ? fetch_line - 6 : 1 ))
   guard_window="$( sed -n "${window_start},$(( fetch_line - 1 ))p" -- "${subject}" )"
   if [[ "${guard_window}" =~ (^|[^[:alnum:]_])else([^[:alnum:]_]|$) ]] \
      || [[ "${guard_window}" =~ update_only ]]; then
      fail "the 'git fetch --recurse-submodules' appears guarded by an update_only conditional -- the fetch is mandatory and must stay unconditional (do not re-add an offline / --update-only fetch skip):
$( printf '%s\n' "${guard_window}" )"
   else
      pass 'the bulk remote fetch is unconditional (mandatory on every invocation)'
   fi
fi

summary_line="===== derivative-update mandatory fetch: $(( test_failures == 0 ? 1 : 0 )) pass, ${test_failures} fail ====="
printf '%s\n' "${summary_line}"
if [ "${test_failures}" -gt 0 ]; then
   exit 1
fi
exit 0
