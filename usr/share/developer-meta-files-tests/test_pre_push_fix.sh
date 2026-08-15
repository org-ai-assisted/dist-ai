#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Canary regression suite for pre-push-fix, the bucket-1 style AUTO-FIXER.
## Drives the REAL, shipped tool as a subprocess (no private copy). Fixture
## bytes are emitted with 'printf %b' octal escapes (\342\200\224 == em dash,
## \303\251 == e-acute) so THIS test source stays ASCII and carries no literal
## trailing whitespace of its own (the fixtures' trailing blanks live inside
## the quoted format argument, not at end-of-source-line).
##
## What is pinned:
##   * confusables + trailing whitespace are fixed; result is ASCII-clean
##   * a non-confusable UTF-8 codepoint (not in the table) is PRESERVED -- the
##     fixer only touches the known set, never guesses (no fixture corruption)
##   * the '## style-ok: allow-non-ascii' waiver suppresses R-001 but not the
##     whitespace strip -- parity with pre-push-static's exemption
##   * an undecodable file and a symlink are skipped, unchanged
##   * --check reports without writing and exits 1 on a dirty file
##   * idempotency
##   * GATE PARITY / round-trip proof: a file that FAILS pre-push-static R-001
##     PASSES it after the fixer runs -- the whole point of fix-then-verify

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

tool_test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
FIX="${tool_test_dir}/../../bin/pre-push-fix"
if [ ! -x "${FIX}" ]; then
   FIX='/usr/bin/pre-push-fix'
fi
if [ ! -x "${FIX}" ]; then
   printf '%s\n' "FATAL: pre-push-fix not found (looked at '${FIX}')." >&2
   exit 1
fi
GATE="${tool_test_dir}/../../bin/pre-push-static"
if [ ! -x "${GATE}" ]; then
   GATE='/usr/bin/pre-push-static'
fi

for prereq in python3 git safe-rm ; do
   if ! type -P "${prereq}" >/dev/null 2>&1 ; then
      printf '%s\n' "FATAL: '${prereq}' not on PATH; this test cannot run." >&2
      exit 1
   fi
done

test_dir="$(mktemp --directory)"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${test_dir}"; }
trap cleanup EXIT

fail=0
note_pass() { printf '%s\n' "PASS: ${1}" ; }
note_fail() { printf '%s\n' "FAIL: ${1}" >&2 ; fail=1 ; }

has_non_ascii() {
   LC_ALL=C grep --quiet --perl-regexp '[^\x00-\x7F]' -- "${1}"
}
has_trailing_ws() {
   grep --perl-regexp --quiet '[[:blank:]]+$' -- "${1}"
}

## --- 1: confusables + trailing whitespace fixed, result ASCII-clean --------
f="${test_dir}/basic.sh"
printf '%b' '#!/bin/bash\n## a \342\200\224 b and \342\200\230hi\342\200\231   \nx=1\t\n' >"${f}"
## Canary: the fixture must actually be dirty, else a no-op fixer "passes".
if has_non_ascii "${f}" ; then
   note_pass "fixture is genuinely dirty (canary)"
else
   note_fail "fixture is not dirty -- canary would let a no-op fixer pass"
fi
"${FIX}" "${f}" >/dev/null 2>&1
if has_non_ascii "${f}" ; then
   note_fail "confusables not fully substituted"
elif grep --quiet --fixed-strings -- '## a -- b' "${f}" \
   && grep --quiet --fixed-strings -- "'hi'" "${f}" ; then
   note_pass "confusables substituted to ASCII"
else
   note_fail "confusable substitution wrong"
fi
if has_trailing_ws "${f}" ; then
   note_fail "trailing whitespace not stripped"
else
   note_pass "trailing whitespace stripped"
fi

## --- 2: a non-confusable UTF-8 codepoint is PRESERVED ----------------------
f="${test_dir}/preserve.py"
printf '%b' '#!/usr/bin/python3\ncaf\303\251 = 1\n' >"${f}"
"${FIX}" "${f}" >/dev/null 2>&1
if has_non_ascii "${f}" ; then
   note_pass "non-confusable UTF-8 preserved (fixer only touches known set)"
else
   note_fail "non-confusable UTF-8 was altered -- fixer guessed, must not"
fi

## --- 3: allow-non-ascii waiver suppresses R-001, not whitespace -----------
f="${test_dir}/waived.sh"
printf '%b' '#!/bin/bash\n## style-ok: allow-non-ascii\ny=\342\200\224   \n' >"${f}"
"${FIX}" "${f}" >/dev/null 2>&1
if has_non_ascii "${f}" && ! has_trailing_ws "${f}" ; then
   note_pass "waiver keeps non-ASCII, whitespace still fixed (gate parity)"
else
   note_fail "waiver behavior wrong"
fi

## --- 4: undecodable file skipped, bytes unchanged -------------------------
f="${test_dir}/binary.sh"
printf '%b' '#!/bin/bash\n# \377\376 raw  \n' >"${f}"
before="$(cksum < "${f}")"
"${FIX}" "${f}" >/dev/null 2>&1
if [ "$(cksum < "${f}")" = "${before}" ] ; then
   note_pass "undecodable file left byte-identical"
else
   note_fail "undecodable file was modified"
fi

## --- 5: symlink skipped ---------------------------------------------------
printf '%b' '#!/bin/bash\nx=1  \n' >"${test_dir}/target.sh"
ln -s target.sh "${test_dir}/alias.sh"
"${FIX}" "${test_dir}/alias.sh" >/dev/null 2>&1
if has_trailing_ws "${test_dir}/target.sh" ; then
   note_pass "symlink skipped (target untouched via the link)"
else
   note_fail "symlink was followed and its target rewritten"
fi

## --- 6: --check reports, writes nothing, exits 1 --------------------------
f="${test_dir}/check.md"
printf '%b' 'a \342\200\224 b\n' >"${f}"
before="$(cksum < "${f}")"
rc=0
"${FIX}" --check "${f}" >/dev/null 2>&1 || rc=$?
if [ "${rc}" -eq 1 ] && [ "$(cksum < "${f}")" = "${before}" ] ; then
   note_pass "--check exits 1 on dirty file and writes nothing"
else
   note_fail "--check misbehaved (rc=${rc})"
fi

## --- 7: idempotency -------------------------------------------------------
f="${test_dir}/idem.sh"
printf '%b' '#!/bin/bash\n## \342\200\224   \n' >"${f}"
"${FIX}" "${f}" >/dev/null 2>&1
first="$(cksum < "${f}")"
"${FIX}" "${f}" >/dev/null 2>&1
if [ "$(cksum < "${f}")" = "${first}" ] ; then
   note_pass "idempotent (second run changes nothing)"
else
   note_fail "not idempotent"
fi

## --- 8: GATE PARITY / round-trip proof ------------------------------------
## A dirty file FAILS pre-push-static R-001; after the fixer it no longer does.
if [ ! -x "${GATE}" ]; then
   printf '%s\n' "FATAL: pre-push-static not found for the parity test." >&2
   exit 1
fi
repo="${test_dir}/repo"
mkdir --parents -- "${repo}"
git -c init.defaultBranch=master -c core.hooksPath=/dev/null init --quiet -- "${repo}"
git -C "${repo}" -c core.hooksPath=/dev/null \
   -c user.name=test -c user.email=test@example.com \
   commit --quiet --allow-empty --message "base"
base_sha="$(git -C "${repo}" rev-parse HEAD)"
printf '%b' '#!/bin/bash\n## comment \342\200\224 here\n' >"${repo}/doc.md"
git -C "${repo}" -c core.hooksPath=/dev/null add --all
git -C "${repo}" -c core.hooksPath=/dev/null \
   -c user.name=test -c user.email=test@example.com \
   commit --quiet --message "dirty"

gate_before="$( cd -- "${repo}" && "${GATE}" "${base_sha}" 2>&1 )" || true
"${FIX}" "${repo}/doc.md" >/dev/null 2>&1
git -C "${repo}" -c core.hooksPath=/dev/null add --all
git -C "${repo}" -c core.hooksPath=/dev/null \
   -c user.name=test -c user.email=test@example.com \
   commit --quiet --message "fixed"
gate_after="$( cd -- "${repo}" && "${GATE}" "${base_sha}" 2>&1 )" || true

if printf '%s\n' "${gate_before}" | grep --quiet --fixed-strings 'R-001' \
   && ! printf '%s\n' "${gate_after}" | grep --quiet --fixed-strings 'R-001' ; then
   note_pass "gate parity: R-001 failed before the fixer, clean after"
else
   note_fail "gate parity broken"
fi

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "pre-push-fix: at least one canary FAILED." >&2
   exit 1
fi
printf '%s\n' "pre-push-fix: all canaries passed."
exit 0
