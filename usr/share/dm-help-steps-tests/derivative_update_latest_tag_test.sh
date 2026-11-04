#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for 'derivative-update --tag latest' tag selection.
##
## THE BUG IT GUARDS: the old selector
##     latest_tag_commit="$(git rev-list --tags --max-count=1)"
##     target_tag="$(git describe --tags -- "${latest_tag_commit}")"
## orders by COMMIT DATE across ALL tags. A non-release tag (sync/backup/local)
## on a newer-dated commit, or a release tag not on the newest-dated commit,
## selects the WRONG tag -- '--tag latest' then moved to a stale/wrong tag, or
## to a non-release tag that fails signature verification. 'git tag | tail' is
## also wrong: default (lexicographic) order puts 18.2.4.10 before 18.2.4.2 and
## sorts non-release tags to the end.
##
## Sources the REAL 'derivative-update' and drives its pure selection helper
## 'derivative_update_latest_release_tag' against crafted repositories, so a
## revert to any naive idiom fails here.
##
## Needs no root, no network, no build. git config is isolated for determinism.

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

subject=""
for candidate in "${DERIVATIVE_UPDATE:-}" "${dm_checkout}/derivative-update"; do
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
## check_runtime.bsh (the 'was_executed' provider the subject sources) rides the
## helper-scripts submodule; its absence means an incomplete checkout, not a
## defect under test.
runtime_lib="${subject%/derivative-update}/packages/kicksecure/helper-scripts/usr/libexec/helper-scripts/check_runtime.bsh"
if [ -z "${subject}" ] || [ ! -r "${runtime_lib}" ]; then
   printf '%s\n' "SKIP: derivative-update / helper-scripts checkout absent (set DERIVATIVE_UPDATE or DERIVATIVE_MAKER_DIR)." >&2
   ## style-ok: allow-skip: the derivative-maker checkout is absent in the standard dist-ai-tests CI job
   exit 77
fi

## Source the real script: 'was_executed' keeps 'main' from running, so this
## only defines the pure helpers (no fetch, no checkout, no strict leak).
# shellcheck disable=SC1090
source "${subject}"
if ! declare -F derivative_update_latest_release_tag >/dev/null; then
   fail "derivative_update_latest_release_tag not defined after sourcing ${subject}"
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi

workdir="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${workdir}"; }
trap cleanup EXIT

## Isolate git from the invoking user's config (e.g. versionsort.suffix) and
## identity so the result is deterministic in any CI environment.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t

## Build a repo under ${workdir}/$1; each later arg is 'DATE|TAG' (empty TAG =
## untagged commit). Echoes the repo path.
mkrepo() {
   local name="$1"; shift
   local dir="${workdir}/${name}" spec date tag
   git init --quiet --initial-branch master -- "${dir}"
   for spec in "$@"; do
      date="${spec%%|*}"; tag="${spec#*|}"
      GIT_COMMITTER_DATE="${date}" git -C "${dir}" commit --quiet --allow-empty \
         --date "${date}" --message "c ${tag:-untagged}"
      [ -z "${tag}" ] || git -C "${dir}" tag -- "${tag}"
   done
   printf '%s\n' "${dir}"
}

## Call the REAL selection helper with the repo as cwd; echo its result or 'NONE'.
select_latest() {
   ( cd -- "$1" && derivative_update_latest_release_tag ) || printf '%s\n' NONE
}

## --- Case A: the regression itself ----------------------------------------
## Highest version (18.2.4.10) is on the OLDEST-dated commit, a double-digit
## component is present, and a junk tag (sync-parent) sits on the NEWEST commit.
repo_a="$(mkrepo a \
   '2024-01-01T00:00:00|18.2.4.10' \
   '2024-06-01T00:00:00|18.2.4.2' \
   '2024-12-01T00:00:00|sync-parent')"
got_a="$(select_latest "${repo_a}")"
if [ "${got_a}" = "18.2.4.10" ]; then
   pass "case A: selected highest-version release 18.2.4.10"
else
   fail "case A: expected 18.2.4.10, got '${got_a}'"
fi

## CANARY: prove the crafted repo actually DEFEATS the old idiom -- otherwise
## case A would pass vacuously even on the broken code.
old_commit="$(git -C "${repo_a}" rev-list --tags --max-count=1)"
old_pick="$(git -C "${repo_a}" describe --tags -- "${old_commit}")"
if [ "${old_pick}" != "18.2.4.10" ]; then
   pass "canary: old 'rev-list --tags' idiom mis-selects '${old_pick}' here"
else
   fail "canary broken: old idiom already picks 18.2.4.10, so case A proves nothing"
fi

## --- Case B: channel-suffixed versions, higher patch wins ------------------
repo_b="$(mkrepo b \
   '2024-01-01T00:00:00|18.2.4.2-developers-only' \
   '2024-02-01T00:00:00|18.2.4.3-developers-only')"
got_b="$(select_latest "${repo_b}")"
if [ "${got_b}" = "18.2.4.3-developers-only" ]; then
   pass "case B: channel-suffixed version sort picks 18.2.4.3-developers-only"
else
   fail "case B: expected 18.2.4.3-developers-only, got '${got_b}'"
fi

## --- Case C: malformed local tag (version with appended _<hash>) excluded --
repo_c="$(mkrepo c \
   '2024-01-01T00:00:00|18.2.4.2-developers-only' \
   '2024-02-01T00:00:00|18.2.4.2-developers-only_deadbeef01')"
got_c="$(select_latest "${repo_c}")"
if [ "${got_c}" = "18.2.4.2-developers-only" ]; then
   pass "case C: malformed '_<hash>' tag excluded, clean release selected"
else
   fail "case C: expected 18.2.4.2-developers-only, got '${got_c}'"
fi

## --- Case D: no release tags -> helper returns non-zero --------------------
repo_d="$(mkrepo d \
   '2024-01-01T00:00:00|sync-parent' \
   '2024-02-01T00:00:00|backup-thing')"
got_d="$(select_latest "${repo_d}")"
if [ "${got_d}" = "NONE" ]; then
   pass "case D: no release tag -> non-zero (no silent wrong pick)"
else
   fail "case D: expected non-zero for a repo with no release tags, got '${got_d}'"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: derivative-update --tag latest selection."
