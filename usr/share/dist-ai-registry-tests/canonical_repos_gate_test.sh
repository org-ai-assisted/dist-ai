#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for ci/canonical-repos-gate.sh, which emits
## allowed=true|false to $GITHUB_OUTPUT based on whether ${THIS_REPO} is in the
## comma-separated ${CANONICAL_REPOS} list. Downstream expensive Coverity steps
## gate on it.
##
## WHY this exists: the membership test wraps both sides in commas
## (",${THIS_REPO}," in ",${CANONICAL_REPOS},") specifically so a repo whose
## name is a SUBSTRING of a canonical entry (org/ba vs org/bar) does not falsely
## pass. A regression to a bare substring match would let a fork burn the
## canonical's quota, or (inverted) silently skip the canonical's scan. Pin
## exact-membership, plus the first/last-element boundaries.
##
## Source-tree test: set DIST_AI_REPO, or run it from a checkout. No source tree
## is FATAL (exit 1), not a skip. No deps, no root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

repo="${DIST_AI_REPO:-}"
if [ -z "${repo}" ]; then
   candidate="${script_dir}/../../.."
   if [ -f "${candidate}/ci/canonical-repos-gate.sh" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi

if [ -z "${repo}" ] || [ ! -f "${repo}/ci/canonical-repos-gate.sh" ]; then
   printf '%s\n' 'FATAL: canonical-repos-gate-test: no dist-ai source tree (set DIST_AI_REPO).' >&2
   exit 1
fi

gate="${repo}/ci/canonical-repos-gate.sh"

work_dir="$(mktemp --directory -- "${TMP}/canonical-repos-gate-test.XXXXXX")"

## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
cleanup_work_dir() {
   safe-rm --recursive --force -- "${work_dir}" || true
   return 0
}

trap cleanup_work_dir EXIT

failures=0
out_file="${work_dir}/github_output"

fail() {
   printf '%s\n' "FAIL: $1" >&2
   failures=$(( failures + 1 ))
}

## Run the gate for a (this_repo, canonical_list) pair; print emitted allowed=.
resolve_allowed() {
   local this_repo="$1" canonical="$2" line value=''
   printf '%s' '' > "${out_file}"
   CANONICAL_REPOS="${canonical}" THIS_REPO="${this_repo}" \
      GITHUB_OUTPUT="${out_file}" bash -- "${gate}" >/dev/null 2>&1
   while IFS= read -r line; do
      case "${line}" in
         'allowed='*)
            value="${line#allowed=}"
            ;;
      esac
   done < "${out_file}"
   printf '%s' "${value}"
}

canonical='org-ai-assisted/bar,org-ai-assisted/foo,org-ai-assisted/baz'

## ---- exact member (middle) -> true ----------------------------------------
if [ "$(resolve_allowed 'org-ai-assisted/foo' "${canonical}")" != 'true' ]; then
   fail 'an exact canonical member did not yield allowed=true'
fi

## ---- exact member (first / last) -> true ----------------------------------
if [ "$(resolve_allowed 'org-ai-assisted/bar' "${canonical}")" != 'true' ]; then
   fail 'the first list element did not yield allowed=true'
fi
if [ "$(resolve_allowed 'org-ai-assisted/baz' "${canonical}")" != 'true' ]; then
   fail 'the last list element did not yield allowed=true'
fi

## ---- non-member -> false --------------------------------------------------
if [ "$(resolve_allowed 'someone/fork' "${canonical}")" != 'false' ]; then
   fail 'a non-member repo did not yield allowed=false'
fi

## ---- substring of a member must NOT match (comma-boundary) -> false --------
if [ "$(resolve_allowed 'org-ai-assisted/ba' "${canonical}")" != 'false' ]; then
   fail 'a substring of a canonical entry falsely matched (comma-boundary regressed)'
fi

## ---- CSV with whitespace after commas: a member must STILL match -----------
## Regression: a normal-CSV space ("a, b") made the exact ',<repo>,' test miss
## the ' <repo>' in the haystack, so a canonical repo silently read as a
## non-member and its Coverity scan was skipped (silent-green).
canonical_spaced='org-ai-assisted/bar, org-ai-assisted/foo, org-ai-assisted/baz'
if [ "$(resolve_allowed 'org-ai-assisted/foo' "${canonical_spaced}")" != 'true' ]; then
   fail 'a canonical member was missed when the CSV had spaces after commas'
fi
if [ "$(resolve_allowed 'org-ai-assisted/baz' "${canonical_spaced}")" != 'true' ]; then
   fail 'the last element was missed with a spaced CSV'
fi
if [ "$(resolve_allowed 'someone/fork' "${canonical_spaced}")" != 'false' ]; then
   fail 'a non-member falsely matched with a spaced CSV'
fi

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "canonical-repos-gate-test: ${failures} check(s) failed" >&2
   exit 1
fi

printf '%s\n' 'canonical-repos-gate-test: all checks passed'
