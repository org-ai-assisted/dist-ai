#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## derivative-update in --update-only mode (how dm-build-official drives EVERY
## build) must NOT do the explicit bulk fetch. --update-only does not move the
## parent (its tag checkout is skipped); it only updates SUBMODULES to the
## recorded pins via 'git submodule update', which fetches any absent pin on its
## OWN. So the bulk 'git fetch' is redundant: the parent-side fetch is unused and
## submodules are fetched on demand by the update.
##
## THE BUG THIS GUARDS: the fetch was unconditional
##     git fetch --recurse-submodules --jobs=100 || error 'Failed to fetch ...'
## which coupled every build to network access AND to the checkout's remote
## transport. A checkout whose origin is an ssh remote with no ssh/keys in the
## build container (or an offline / air-gapped build) then died at this line even
## though a consistent checkout (pins already present) needs no network at all,
## and an absent pin is fetched on demand by the submodule update regardless.
##
## This is a SOURCE guard: the end-to-end path first runs git_sanity_test, which
## needs real OpenPGP-signed commits + keys, so it cannot be fixtured cheaply
## here -- it is exercised by the green CI dry-run lane. This asserts the fetch is
## reachable ONLY when update_only is not true, which is what the fix guarantees
## and what a regression would undo. Fails loudly on the old unconditional fetch.

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
   ## The window ABOVE the fetch (up to the fetch line) must carry the
   ## update-only guard that keeps the fetch out of --update-only builds. The old
   ## unconditional fetch had only the 'Fetch new code from remote.' comment here.
   window_start=$(( fetch_line > 14 ? fetch_line - 14 : 1 ))
   guard_window="$( sed -n "${window_start},${fetch_line}p" -- "${subject}" )"
   if [[ "${guard_window}" =~ update_only[^$'\n']*!=[^$'\n']*\"true\" ]] \
      || { [[ "${guard_window}" =~ update_only[^$'\n']*=[^$'\n']*\"true\" ]] \
           && [[ "${guard_window}" =~ else ]]; }; then
      pass 'the remote fetch is guarded by --update-only (skipped in build/verify-only mode)'
   else
      fail "the 'git fetch --recurse-submodules' is not guarded by an update_only conditional -- the unconditional-fetch regression is back (offline / ssh-remote builds will die here):
$( printf '%s\n' "${guard_window}" )"
   fi
fi

summary_line="===== derivative-update offline fetch: $(( test_failures == 0 ? 1 : 0 )) pass, ${test_failures} fail ====="
printf '%s\n' "${summary_line}"
if [ "${test_failures}" -gt 0 ]; then
   exit 1
fi
exit 0
