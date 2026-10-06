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

## Decide whether derivative-update's bulk remote fetch is PRESENT in update_repo() and a
## DIRECT, un-nested statement of its body; print a diagnostic and return non-zero
## otherwise. A best-effort SOURCE tripwire -- per this file's header the AUTHORITATIVE
## guarantee that the fetch is REACHED on every path is the CI dry-run lane, not this
## textual check. Kept parser-free (policy: no bash block parser). A function so the CANARY
## below exercises the SAME logic on planted fixtures.
##
## Reliably catches, textually and without dataflow:
##   - the fetch removed, renamed out of update_repo(), or moved elsewhere -- the search is
##     SCOPED to update_repo()'s body, so a stray fetch in another function cannot satisfy it;
##   - the fetch commented out -- anchor on the EXECUTED line ('#'-comment lines excluded),
##     so the maintainer note that merely DOCUMENTS the fetch is not mistaken for it;
##   - the fetch DIRECTLY wrapped in a conditional -- it must sit at update_repo()'s 2-space
##     body indent, and under the project's enforced 2-space style any wrapping block
##     indents it deeper.
## OUT of scope (needs dataflow -> the CI dry-run lane): a fetch left un-nested but made
## UNREACHABLE under --update-only by an early 'return'/'exit' in a PRECEDING block.
## update_repo() already contains a legitimate 'if update_only' block above the fetch, so a
## textual update_only/else token scan cannot distinguish a skip-injection from it -- that
## is deliberately NOT attempted here (a token scan either false-positives on the real block
## or false-negatives on a far opener).
fetch_is_unconditional() {
   local fsubject body fetch_text indent
   fsubject="$1"

   ## Scope to update_repo()'s body: its opener line to the next column-0 '}'.
   body="$( sed -n '/^update_repo() {$/,/^}$/p' -- "${fsubject}" )"
   if [ -z "${body}" ]; then
      printf 'no update_repo() {...} in %s (the function moved or was renamed -- update this test)\n' "${fsubject}"
      return 1
   fi

   ## First EXECUTED fetch in the body ('#'-comment lines excluded). grep -m1 exits 0 on a
   ## match, non-zero when absent; '|| true' keeps errexit from aborting on the absent case.
   fetch_text="$( printf '%s\n' "${body}" | grep -m1 -E '^[[:space:]]*git fetch --recurse-submodules' || true )"
   if [ -z "${fetch_text}" ]; then
      printf 'no EXECUTED "git fetch --recurse-submodules" inside update_repo() in %s (removed, renamed, or commented out)\n' "${fsubject}"
      return 1
   fi

   ## A direct statement of update_repo() sits at its 2-space base indent; a wrapping block
   ## deepens it (project style keeps nesting indented).
   indent="${fetch_text%%[! ]*}"
   if [ "${#indent}" -ne 2 ]; then
      printf 'the fetch is indented %d space(s), not update_repo 2-space base indent -- it looks nested in a conditional:\n%s\n' "${#indent}" "${fetch_text}"
      return 1
   fi
   return 0
}

if verdict="$( fetch_is_unconditional "${subject}" )"; then
   pass 'the bulk remote fetch is present and a direct, un-nested statement of update_repo()'
else
   fail "the bulk remote fetch failed the mandatory/un-nested check (do not remove, comment out, move, or wrap it; reachability under --update-only is the CI dry-run lane's job): ${verdict}"
fi

## --- CANARY: the check REJECTS each textual re-introduction shape it claims to catch
## (commented out, moved to another function, directly wrapped) and ACCEPTS the real-file
## shape (a 2-space fetch below the legitimate 'if update_only' block). RED on a planted
## bug, GREEN on the real file. An unreachable-via-early-return skip is out of scope (CI
## dry-run lane), so it is not asserted here. ---
canary_dir="$( mktemp -d )"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${canary_dir}"; }
trap cleanup EXIT

printf '%s\n' \
   'update_repo() {' \
   '  ## the mandatory fetch (documented below)' \
   "  git fetch --recurse-submodules --jobs=100 || error 'Failed to fetch from remote!'" \
   '}' > "${canary_dir}/clean"

printf '%s\n' \
   'update_repo() {' \
   "  ## git fetch --recurse-submodules --jobs=100 || error 'documented, not executed'" \
   '  true' \
   '}' > "${canary_dir}/comment_only"

## Fetch DIRECTLY wrapped: nesting deepens its indent past the 2-space base.
# shellcheck disable=SC2016  # literal fixture text: '${update_only:-}' must NOT expand
printf '%s\n' \
   'update_repo() {' \
   '  if [ "${update_only:-}" != "true" ]; then' \
   "    git fetch --recurse-submodules --jobs=100 || error 'Failed to fetch from remote!'" \
   '  fi' \
   '}' > "${canary_dir}/wrapped"

## Fetch present only in a DEAD sibling function -- update_repo() itself never fetches.
printf '%s\n' \
   'unused() {' \
   "  git fetch --recurse-submodules --jobs=100 || error 'Failed to fetch from remote!'" \
   '}' \
   'update_repo() {' \
   '  true' \
   '}' > "${canary_dir}/other_function"

## The REAL-FILE shape: a legitimate 'if update_only' block (the target_tag check) ABOVE
## the comment and the 2-space fetch. Must be ACCEPTED -- the check must not false-positive
## on the pre-existing update_only block.
# shellcheck disable=SC2016  # literal fixture text: '${update_only:-}' must NOT expand
printf '%s\n' \
   'update_repo() {' \
   '  if [ "${update_only:-}" = "true" ]; then' \
   '    target_tag="$(git describe --exact-match --tags HEAD 2>/dev/null)" || target_tag=""' \
   '    if [ -z "${target_tag}" ]; then' \
   "      error 'no tag'" \
   '    fi' \
   '  fi' \
   '' \
   '  ## Note to AI agents: mandatory fetch below.' \
   "  git fetch --recurse-submodules --jobs=100 || error 'Failed to fetch from remote!'" \
   '}' > "${canary_dir}/real_shape"

if fetch_is_unconditional "${canary_dir}/clean" >/dev/null; then
   pass 'canary: a clean unconditional fetch fixture is accepted'
else
   fail 'canary broken: the clean unconditional fetch fixture was rejected'
fi
if ! fetch_is_unconditional "${canary_dir}/comment_only" >/dev/null; then
   pass 'canary: a commented-out (documented, not executed) fetch is rejected'
else
   fail 'canary broken: a commented-out fetch passed'
fi
if ! fetch_is_unconditional "${canary_dir}/wrapped" >/dev/null; then
   pass 'canary: a directly wrapped (nested, deeper-indent) fetch is rejected'
else
   fail 'canary broken: a directly wrapped fetch passed'
fi
if ! fetch_is_unconditional "${canary_dir}/other_function" >/dev/null; then
   pass 'canary: a fetch only in a dead sibling function is rejected (scoped to update_repo)'
else
   fail 'canary broken: a fetch outside update_repo passed'
fi
if fetch_is_unconditional "${canary_dir}/real_shape" >/dev/null; then
   pass 'canary: the real-file shape (fetch below the legitimate update_only block) is accepted'
else
   fail 'canary broken: the real-file shape was wrongly rejected (false positive on the legit update_only block)'
fi

## 6 assertions always run (the real check + five canary fixtures), none early-exit.
summary_line="===== derivative-update mandatory fetch: $(( 6 - test_failures )) pass, ${test_failures} fail ====="
printf '%s\n' "${summary_line}"
if [ "${test_failures}" -gt 0 ]; then
   exit 1
fi
exit 0
