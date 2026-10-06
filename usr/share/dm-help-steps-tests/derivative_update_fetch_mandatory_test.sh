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

## Decide whether derivative-update's bulk remote fetch is both PRESENT and
## UNCONDITIONAL; print a diagnostic and return non-zero otherwise. A function so the
## CANARY below exercises the SAME logic against planted-bug fixtures.
##
## Deliberately parser-free (we do NOT reinvent a bash block parser), three simple signals:
##   - anchor on the EXECUTED fetch: a leading-'#' comment that merely DOCUMENTS the fetch
##     (the header note anticipates one) starts with '#' and must not be mistaken for the
##     statement, so '| head -1' can no longer latch onto a comment occurrence;
##   - the fetch must sit at update_repo's 2-space body indent -- wrapping it in ANY
##     conditional deepens its indent, a robust signal wherever the 'if' opener sits,
##     so detection no longer depends on a fixed preceding-line window;
##   - plus an else/update_only scan of the executable (non-comment) lines just above.
fetch_is_unconditional() {
   local fsubject fetch_line fetch_text indent guard_window window_start
   fsubject="$1"

   ## '|| true': with no executed match (a comment-only / moved fetch) the pipeline
   ## returns non-zero, which errexit would otherwise abort on before the check below.
   fetch_line="$( grep -nE '^[[:space:]]*git fetch --recurse-submodules' -- "${fsubject}" | head -1 | cut -d: -f1 || true )"
   if [ -z "${fetch_line}" ]; then
      printf 'no EXECUTED "git fetch --recurse-submodules" in %s (the fetch moved or became comment-only -- update this test if it legitimately moved)\n' "${fsubject}"
      return 1
   fi

   fetch_text="$( sed -n "${fetch_line}p" -- "${fsubject}" )"
   indent="${fetch_text%%[! ]*}"
   if [ "${#indent}" -ne 2 ]; then
      printf 'the fetch at line %d is indented %d space(s), not the unconditional 2-space body indent of update_repo -- it looks wrapped in a conditional:\n%s\n' "${fetch_line}" "${#indent}" "${fetch_text}"
      return 1
   fi

   window_start=$(( fetch_line > 6 ? fetch_line - 6 : 1 ))
   guard_window="$( sed -n "${window_start},$(( fetch_line - 1 ))p" -- "${fsubject}" | grep -vE '^[[:space:]]*#' || true )"
   if [[ "${guard_window}" =~ (^|[^[:alnum:]_])else([^[:alnum:]_]|$) ]] || [[ "${guard_window}" =~ update_only ]]; then
      printf 'the fetch at line %d appears guarded by an update_only/else conditional:\n%s\n' "${fetch_line}" "${guard_window}"
      return 1
   fi
   return 0
}

if verdict="$( fetch_is_unconditional "${subject}" )"; then
   pass 'the bulk remote fetch is unconditional (mandatory on every invocation)'
else
   fail "the bulk remote fetch is not proven mandatory/unconditional (do not re-add an offline / --update-only fetch skip): ${verdict}"
fi

## --- CANARY: prove the verdict REJECTS the two re-introduction shapes this guard
## exists to stop (a comment-only fetch, and an update_only-wrapped fetch) and ACCEPTS a
## clean fixture. RED on a planted bug, GREEN on the real file. ---
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

# shellcheck disable=SC2016  # literal fixture text: '${update_only:-}' must NOT expand
printf '%s\n' \
   'update_repo() {' \
   '  if [ "${update_only:-}" != "true" ]; then' \
   "    git fetch --recurse-submodules --jobs=100 || error 'Failed to fetch from remote!'" \
   '  fi' \
   '}' > "${canary_dir}/wrapped"

## Wrap whose 'if update_only' opener sits well ABOVE the 6-line token window, so the
## token scan alone cannot see it; only the 2-space indentation invariant catches it.
# shellcheck disable=SC2016  # literal fixture text: '${update_only:-}' must NOT expand
printf '%s\n' \
   'update_repo() {' \
   '  if [ "${update_only:-}" != "true" ]; then' \
   '    true "a"' \
   '    true "b"' \
   '    true "c"' \
   '    true "d"' \
   '    true "e"' \
   '    true "f"' \
   "    git fetch --recurse-submodules --jobs=100 || error 'Failed to fetch from remote!'" \
   '  fi' \
   '}' > "${canary_dir}/wrapped_far"

if fetch_is_unconditional "${canary_dir}/clean" >/dev/null; then
   pass 'canary: a clean unconditional fetch fixture is accepted'
else
   fail 'canary broken: the clean unconditional fetch fixture was rejected'
fi
if ! fetch_is_unconditional "${canary_dir}/comment_only" >/dev/null; then
   pass 'canary: a comment-only (documented, not executed) fetch is rejected'
else
   fail 'canary broken: a comment-only fetch passed as unconditional'
fi
if ! fetch_is_unconditional "${canary_dir}/wrapped" >/dev/null; then
   pass 'canary: an update_only-wrapped fetch is rejected'
else
   fail 'canary broken: an update_only-wrapped fetch passed as unconditional'
fi
if ! fetch_is_unconditional "${canary_dir}/wrapped_far" >/dev/null; then
   pass 'canary: a wrap whose opener is above the token window is still rejected (indent invariant)'
else
   fail 'canary broken: an out-of-window update_only wrap passed as unconditional'
fi

## 5 assertions always run (the real check + four canary fixtures), none early-exit.
summary_line="===== derivative-update mandatory fetch: $(( 5 - test_failures )) pass, ${test_failures} fail ====="
printf '%s\n' "${summary_line}"
if [ "${test_failures}" -gt 0 ]; then
   exit 1
fi
exit 0
