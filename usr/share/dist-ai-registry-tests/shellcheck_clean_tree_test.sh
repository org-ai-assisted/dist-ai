#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guard: dist-ai's OWN shell tree stays shellcheck-clean with NO project
## .shellcheckrc. This is what makes the .shellcheckrc removal permanent and
## regression-proof: without it a future file could reintroduce a suppressed
## shellcheck code, or a .shellcheckrc could reappear to blanket-silence one,
## and nobody would notice. Runs the AUTHORITATIVE gate (dist-ai-style --check)
## over the tree and greps for shellcheck [SC....] findings only -- the tree's
## pre-existing non-shellcheck R-debt on files this program never touched is out
## of scope and must not false-fail this guard.
##
## Source-tree test: set DIST_AI_REPO, or run from a checkout. Without one it
## is a FATAL environment error (exit 1), not a skip -- the guard must not go
## silently green when it never checked a tree. No root, no network.

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
   if [ -f "${candidate}/usr/bin/dist-ai-style" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi
if [ -z "${repo}" ] || [ ! -f "${repo}/usr/bin/dist-ai-style" ]; then
   printf '%s\n' 'FAIL: shellcheck-clean-tree: no dist-ai source tree (set DIST_AI_REPO).' >&2
   exit 1
fi

gate="${repo}/usr/bin/dist-ai-style"

## Required deps: fail LOUD (exit 1), never skip -- a vanished gate/shellcheck
## must not silently stop guarding.
if ! type -P shellcheck >/dev/null; then
   printf '%s\n' 'FAIL: shellcheck not on PATH (apt-get install shellcheck); the guard cannot run' >&2
   exit 1
fi

fail=0

## check (1) predicate, SHARED by the live check and canary A -- so the canary
## exercises the REAL detection, not merely that `touch` created a file. Returns
## 0 (true) when the dir has NO .shellcheckrc (ok), non-zero when one is present.
shellcheckrc_absent() {
   [ ! -e "$1/.shellcheckrc" ]
}

## (1) The project .shellcheckrc must NOT exist. Its removal is the whole point;
## a reappearance would blanket-silence the codes this program eliminated.
if ! shellcheckrc_absent "${repo}"; then
   printf '%s\n' "FAIL: a .shellcheckrc reappeared at '${repo}/.shellcheckrc'; the removal must stay permanent" >&2
   fail=1
fi

## (2) No shellcheck code fires anywhere in dist-ai's own shell tree, under the
## authoritative gate (so the absent-sibling SC1091 tolerance + source-path
## resolution match production). Grep the [SC....] findings only; ignore the
## gate's non-zero exit from pre-existing non-shellcheck R-debt on untouched files.
gate_out="$(
   cd -- "${repo}" || exit 0
   "${gate}" --check . 2>&1 || true
)"

## Non-vacuous: the gate must actually have run to a verdict. If it errored out
## before checking (empty / no summary), a "no [SC] lines" read would be a false
## green -- fail closed.
if ! grep --quiet --extended-regexp 'check\(s\) (failed|passed)|all static checks passed' <<< "${gate_out}"; then
   printf '%s\n' 'FAIL: dist-ai-style produced no completion summary; the tree was not actually checked' >&2
   printf '%s\n' "${gate_out}" | tail -20 >&2
   fail=1
fi

sc_lines="$( printf '%s\n' "${gate_out}" | grep --extended-regexp '\[SC[0-9]+\]' || true )"
if [ -n "${sc_lines}" ]; then
   printf '%s\n' 'FAIL: shellcheck codes fire in dist-ai shell tree (the rc removal is not clean):' >&2
   printf '%s\n' "${sc_lines}" >&2
   fail=1
fi

## --- CANARY (both ways): prove this guard actually CATCHES a regression, not
## just passes on today's clean tree. Run the two checks against throwaway
## fixtures and assert they trip. A guard that never fails guards nothing.

work_dir="$(mktemp --directory -- "${TMP}/shellcheck-clean-tree-canary.XXXXXX")"
# shellcheck disable=SC2317  # invoked via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work_dir}"; }
trap cleanup EXIT

## Canary A: check (1)'s predicate must DETECT a planted .shellcheckrc -- prove the
## detection actually trips, not merely that `touch` created a file (the old check
## only asserted the fixture existed, so it exercised check (1) not at all).
touch -- "${work_dir}/.shellcheckrc"
if shellcheckrc_absent "${work_dir}"; then
   printf '%s\n' 'FAIL(canary A): check (1) did NOT detect a planted .shellcheckrc -- the guard would not catch an rc reappearance' >&2
   fail=1
fi

## Canary B: a fresh SC2016 violation in a shell file must be caught by the gate
## (no rc present -> the code fires). Prove the detection, not just the clean tree.
cat > "${work_dir}/canary.sh" <<'CANARY'
#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C
y='value'
printf '%s\n' 'literal $y stays literal'
CANARY
canary_out="$( "${gate}" --check "${work_dir}/canary.sh" 2>&1 || true )"
if ! grep --quiet '\[SC2016\]' <<< "${canary_out}"; then
   printf '%s\n' 'FAIL(canary B): the gate did NOT flag a planted SC2016 violation -- the guard would not catch a real regression' >&2
   printf '%s\n' "${canary_out}" | tail -10 >&2
   fail=1
fi

if [ "${fail}" -eq 0 ]; then
   printf '%s\n' 'PASS: dist-ai shell tree shellcheck-clean, no .shellcheckrc, canary catches both regressions'
fi
exit "${fail}"
