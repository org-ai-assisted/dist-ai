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

for prereq in python3 git safe-rm shellcheck ; do
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

## --- 1: always-safe confusables + trailing whitespace, result ASCII-clean --
## em dash, ellipsis, arrow -- the structure-safe set applied in code too.
f="${test_dir}/basic.sh"
printf '%b' '#!/bin/bash\n## a \342\200\224 b \342\200\246 c \342\206\222 d   \nx=1\t\n' >"${f}"
## Canary: the fixture must actually be dirty, else a no-op fixer "passes".
if has_non_ascii "${f}" ; then
   note_pass "fixture is genuinely dirty (canary)"
else
   note_fail "fixture is not dirty -- canary would let a no-op fixer pass"
fi
"${FIX}" "${f}" >/dev/null 2>&1
if has_non_ascii "${f}" ; then
   note_fail "confusables not fully substituted"
elif grep --quiet --fixed-strings -- '## a -- b ... c -> d' "${f}" ; then
   note_pass "always-safe confusables substituted to ASCII"
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

## --- 7b: smart quotes are markup-only (safe in code) --------------------
## In a .sh file a smart apostrophe stays (rewriting it to ASCII ' could break
## a single-quoted string); the em dash on the same line is still fixed.
f="${test_dir}/quotes.sh"
printf '%b' '#!/bin/bash\nx=\342\200\230hi\342\200\231 \342\200\224 y\n' >"${f}"
"${FIX}" "${f}" >/dev/null 2>&1
if has_non_ascii "${f}" && grep --quiet --fixed-strings -- ' -- ' "${f}" ; then
   note_pass "smart quotes kept in code, em dash still fixed"
else
   note_fail "smart-quote-in-code handling wrong"
fi
## In a .md file the same smart quotes ARE fixed (quotes are content there).
f="${test_dir}/quotes.md"
printf '%b' 'a \342\200\230hi\342\200\231 b\n' >"${f}"
"${FIX}" "${f}" >/dev/null 2>&1
if ! has_non_ascii "${f}" && grep --quiet --fixed-strings -- "'hi'" "${f}" ; then
   note_pass "smart quotes fixed in markup"
else
   note_fail "smart-quote-in-markup handling wrong"
fi

## --- 7c: no-break space is actually substituted --------------------------
f="${test_dir}/nbsp.sh"
printf '%b' '#!/bin/bash\nx=\302\2401\n' >"${f}"
"${FIX}" "${f}" >/dev/null 2>&1
if ! has_non_ascii "${f}" ; then
   note_pass "no-break space substituted to a plain space"
else
   note_fail "no-break space not substituted"
fi

## --- 7d: waiver grammar parity (no space after the colon) ----------------
## The gate accepts '##style-ok:allow-non-ascii'; the fixer must too, or it
## rewrites a file the gate exempts.
f="${test_dir}/waiver2.sh"
printf '%b' '#!/bin/bash\n##style-ok:allow-non-ascii\ny=\342\200\224\n' >"${f}"
"${FIX}" "${f}" >/dev/null 2>&1
if has_non_ascii "${f}" ; then
   note_pass "waiver honored without whitespace after the colon (gate parity)"
else
   note_fail "waiver grammar not in lockstep with the gate"
fi

## --- 7e: --staged outside a repo is an ERROR, not a false green ----------
nonrepo="${test_dir}/nonrepo"
mkdir --parents -- "${nonrepo}"
rc=0
( cd -- "${nonrepo}" && "${FIX}" --staged >/dev/null 2>&1 ) || rc=$?
if [ "${rc}" -eq 2 ] ; then
   note_pass "--staged discovery failure exits 2 (no false green)"
else
   note_fail "--staged outside a repo returned ${rc}, expected 2"
fi

## --- 7f: R-172 temp-dir mkdir short '-m' -> long '--mode=' -----------------
## The command word sits right after a '\n' escape (no real separator), so the
## fixture literal never trips the gate's own R-172 scan of THIS test file.
f="${test_dir}/mkdirmode.sh"
printf '%b' '#!/bin/bash\nmkdir -m 700 -- "$TMPDIR"\nmkdir -m700 -- "$TMP"\n' >"${f}"
"${FIX}" "${f}" >/dev/null 2>&1
if [ "$(grep --count --fixed-strings -- '--mode=700' "${f}")" -eq 2 ] \
   && ! grep --quiet --extended-regexp -- '(^|[[:space:]])-m' "${f}" ; then
   note_pass "R-172 short -m upgraded to --mode= (spaced and attached)"
else
   note_fail "R-172 short-mode upgrade wrong"
fi
first="$(cksum < "${f}")"
"${FIX}" "${f}" >/dev/null 2>&1
if [ "$(cksum < "${f}")" = "${first}" ] ; then
   note_pass "R-172 upgrade idempotent"
else
   note_fail "R-172 upgrade not idempotent"
fi

## --- 7g: the missing-mode form is NOT auto-fixed (stays a gate FAIL) -------
## '--mode' must never be removed and the fixer must never fabricate a mode:
## re-merging a split 'chmod' is a multi-line change, out of the bucket-1
## remit. The file is left byte-identical for pre-push-static to report.
f="${test_dir}/mkdirnomode.sh"
printf '%b' '#!/bin/bash\nmkdir --parents -- "$TMPDIR"\n' >"${f}"
before="$(cksum < "${f}")"
"${FIX}" "${f}" >/dev/null 2>&1
if [ "$(cksum < "${f}")" = "${before}" ] ; then
   note_pass "R-172 leaves the missing-mode form for the gate (not auto-fixed)"
else
   note_fail "R-172 fixer altered a form it must not"
fi

## --- 7h: a bundled '-pm700' is left for the gate (conservative) ------------
f="${test_dir}/mkdirbundle.sh"
printf '%b' '#!/bin/bash\nmkdir -pm700 -- "$TMPDIR"\n' >"${f}"
before="$(cksum < "${f}")"
"${FIX}" "${f}" >/dev/null 2>&1
if [ "$(cksum < "${f}")" = "${before}" ] ; then
   note_pass "R-172 leaves bundled -pm700 for the gate (conservative)"
else
   note_fail "R-172 rewrote a bundled short option unsafely"
fi

## --- 7i: a non-shell file with the pattern is untouched -------------------
f="${test_dir}/doc-mkdir.md"
## 'mkdir' at line start (after the '\n' escape), so this test SOURCE carries
## no real 'mkdir ... $TMPDIR' separator that the gate's own R-172 scan would
## flag -- while the fixture CONTENT still exercises the transform's matcher.
printf '%b' 'mkdir -m 700 -- "$TMPDIR"\n' >"${f}"
before="$(cksum < "${f}")"
"${FIX}" "${f}" >/dev/null 2>&1
if [ "$(cksum < "${f}")" = "${before}" ] ; then
   note_pass "R-172 confined to shell files (markdown untouched)"
else
   note_fail "R-172 rewrote a non-shell file"
fi

## --- 7j: SC2174 disable inserted for the atomic --parents --mode form -----
## The atomic idempotent 'mkdir --parents --mode=' trips SC2174 by design; the
## fixer inserts the disable so R-172's own mandated form stays gate-green. It
## does NOT insert one for a plain '--mode' mkdir (no -p, so no SC2174), and it
## never doubles an existing disable.
f="${test_dir}/mkdirparents.sh"
printf '%b' '#!/bin/bash\nmkdir --parents -m 700 -- "$TMPDIR"\nmkdir --mode=700 -- "$TMP"\n' >"${f}"
"${FIX}" "${f}" >/dev/null 2>&1
if [ "$(grep --count --fixed-strings -- 'disable=SC2174' "${f}")" -eq 1 ] \
   && grep --quiet --fixed-strings -- 'mkdir --parents --mode=700' "${f}" ; then
   note_pass "R-172 inserts one SC2174 disable for --parents --mode (not for plain --mode)"
else
   note_fail "R-172 SC2174 disable insertion wrong"
fi
first="$(cksum < "${f}")"
"${FIX}" "${f}" >/dev/null 2>&1
if [ "$(cksum < "${f}")" = "${first}" ] ; then
   note_pass "R-172 SC2174 disable insertion idempotent (not doubled)"
else
   note_fail "R-172 SC2174 disable insertion not idempotent"
fi

## --- 7k: the disable is NOT wedged into a '\'-continuation -----------------
## A temp mkdir that continues a '\'-terminated line must not get a comment
## inserted between the two -- that would break the continuation. The fixer
## leaves such a line alone (SC2174 there is a rare human fix).
f="${test_dir}/mkdircont.sh"
# shellcheck disable=SC2174
printf '%b' '#!/bin/bash\ntrue \\\n&& mkdir --parents --mode=700 -- "$TMPDIR"\n' >"${f}"
before="$(cksum < "${f}")"
"${FIX}" "${f}" >/dev/null 2>&1
if [ "$(cksum < "${f}")" = "${before}" ] \
   && ! grep --quiet --fixed-strings -- 'disable=SC2174' "${f}" ; then
   note_pass "R-172 does not insert a disable into a line continuation"
else
   note_fail "R-172 broke a '\\'-continuation with an inserted disable"
fi

## --- 7l: the rewrite is scoped to the mkdir command, not the whole line ----
## A second command sharing the line (its own '-m', or a mode belonging to it)
## must be left byte-for-byte alone -- only the temp-dir mkdir's own '-m' is
## upgraded.
f="${test_dir}/mkdirmulti.sh"
printf '%b' '#!/bin/bash\nmkdir -m 700 -- "$TMPDIR" && install -m 755 -- a b\nmkdir -- "$TMPDIR"; other -m700 arg\n' >"${f}"
"${FIX}" "${f}" >/dev/null 2>&1
if [ "$(grep --count --fixed-strings -- 'mkdir --mode=700' "${f}")" -eq 1 ] \
   && grep --quiet --fixed-strings -- 'install -m 755' "${f}" \
   && grep --quiet --fixed-strings -- 'other -m700' "${f}" \
   && ! grep --quiet --fixed-strings -- 'install --mode' "${f}" \
   && ! grep --quiet --fixed-strings -- 'other --mode' "${f}" ; then
   note_pass "R-172 upgrade scoped to the mkdir command (sibling commands' -m preserved)"
else
   note_fail "R-172 upgrade leaked into another command on the line"
fi

## --- 7m: reviewer edge cases -- the rewrite stays provably safe -----------
## An '-m' inside a quoted path or after '--' is a literal directory name, not
## a flag, and must never be rewritten.
f="${test_dir}/mkdiredge.sh"
printf '%b' '#!/bin/bash\nmkdir "$TMPDIR/keep -m 700 name"\nmkdir -- -m 700 "$TMPDIR"\n' >"${f}"
before="$(cksum < "${f}")"
"${FIX}" "${f}" >/dev/null 2>&1
if [ "$(cksum < "${f}")" = "${before}" ] ; then
   note_pass "R-172 leaves an -m inside a quoted path / after -- untouched"
else
   note_fail "R-172 rewrote a literal directory name"
fi
## A backtick command substitution is command position -> the mkdir is upgraded.
f="${test_dir}/mkdirbtick.sh"
printf '%b' '#!/bin/bash\nfoo=`mkdir --mode=700 -- "$TMPDIR"`\n' >"${f}"
"${FIX}" "${f}" >/dev/null 2>&1
if grep --quiet --fixed-strings -- '--mode=700' "${f}" \
   && ! grep --quiet --extended-regexp -- '(^|[[:space:]])-m' "${f}" ; then
   note_pass "R-172 upgrades a backtick-substitution mkdir"
else
   note_fail "R-172 missed a backtick-substitution mkdir"
fi
## The allow-mkdir-no-mode waiver disables the fixer too (lockstep with the gate).
f="${test_dir}/mkdirwaiver.sh"
printf '%b' '#!/bin/bash\n## style-ok: allow-mkdir-no-mode\nmkdir -m 700 -- "$TMPDIR"\n' >"${f}"
before="$(cksum < "${f}")"
"${FIX}" "${f}" >/dev/null 2>&1
if [ "$(cksum < "${f}")" = "${before}" ] ; then
   note_pass "R-172 honors the allow-mkdir-no-mode waiver (fixer/gate parity)"
else
   note_fail "R-172 rewrote a file that waived the rule"
fi
## The SC2174 skip is exact: 'SC21745' is a different code and must not mask the
## required directive, which is still inserted (as its own whole line).
f="${test_dir}/mkdirsc.sh"
printf '%b' '#!/bin/bash\n# shellcheck disable=SC21745\nmkdir -p --mode=700 -- "$TMPDIR"\n' >"${f}"
"${FIX}" "${f}" >/dev/null 2>&1
if grep --quiet --line-regexp --fixed-strings -- '# shellcheck disable=SC2174' "${f}" ; then
   note_pass "R-172 SC2174 skip is exact (SC21745 does not mask it)"
else
   note_fail "R-172 SC2174 boundary wrong (directive not inserted)"
fi
## An EVEN run of trailing backslashes is an escaped backslash, not a line
## continuation, so the disable IS inserted above the next mkdir.
f="${test_dir}/mkdireven.sh"
printf '%b' '#!/bin/bash\necho \\\\\nmkdir -p --mode=700 -- "$TMPDIR"\n' >"${f}"
"${FIX}" "${f}" >/dev/null 2>&1
if grep --quiet --line-regexp --fixed-strings -- '# shellcheck disable=SC2174' "${f}" ; then
   note_pass "R-172 treats an even '\\\\' run as not a continuation"
else
   note_fail "R-172 mis-read an escaped backslash as a line continuation"
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

if grep --quiet --fixed-strings 'R-001' <<< "${gate_before}" \
   && ! grep --quiet --fixed-strings 'R-001' <<< "${gate_after}" ; then
   note_pass "gate parity: R-001 failed before the fixer, clean after"
else
   note_fail "gate parity broken"
fi

## --- 8b: R-172 gate parity -- short -m FAILS the gate, --mode= passes ------
printf '%b' '#!/bin/bash\nmkdir -m 700 -- "$TMPDIR"\n' >"${repo}/tmpdir.sh"
git -C "${repo}" -c core.hooksPath=/dev/null add --all
git -C "${repo}" -c core.hooksPath=/dev/null \
   -c user.name=test -c user.email=test@example.com \
   commit --quiet --message "r172 dirty"
r172_before="$( cd -- "${repo}" && "${GATE}" "${base_sha}" 2>&1 )" || true
"${FIX}" "${repo}/tmpdir.sh" >/dev/null 2>&1
git -C "${repo}" -c core.hooksPath=/dev/null add --all
git -C "${repo}" -c core.hooksPath=/dev/null \
   -c user.name=test -c user.email=test@example.com \
   commit --quiet --message "r172 fixed"
r172_after="$( cd -- "${repo}" && "${GATE}" "${base_sha}" 2>&1 )" || true
if grep --quiet --fixed-strings 'R-172' <<< "${r172_before}" \
   && ! grep --quiet --fixed-strings 'R-172' <<< "${r172_after}" ; then
   note_pass "gate parity: R-172 short -m failed before the fixer, clean after"
else
   note_fail "R-172 gate parity broken"
fi

## --- 8c: R-172 atomic --parents form -- fixer clears R-172 AND SC2174 ------
## 'mkdir --parents -m 700' fails BOTH R-172 (short -m) and shellcheck SC2174
## (-p with -m). After the fixer -- '--mode=' plus the inserted disable -- the
## gate reports NEITHER, proving the SC2174 insertion actually satisfies
## shellcheck rather than trading one failure for another.
printf '%b' '#!/bin/bash\nmkdir --parents -m 700 -- "$TMPDIR"\n' >"${repo}/tmpparents.sh"
git -C "${repo}" -c core.hooksPath=/dev/null add --all
git -C "${repo}" -c core.hooksPath=/dev/null \
   -c user.name=test -c user.email=test@example.com \
   commit --quiet --message "r172 parents dirty"
r172p_before="$( cd -- "${repo}" && "${GATE}" "${base_sha}" 2>&1 )" || true
"${FIX}" "${repo}/tmpparents.sh" >/dev/null 2>&1
git -C "${repo}" -c core.hooksPath=/dev/null add --all
git -C "${repo}" -c core.hooksPath=/dev/null \
   -c user.name=test -c user.email=test@example.com \
   commit --quiet --message "r172 parents fixed"
r172p_after="$( cd -- "${repo}" && "${GATE}" "${base_sha}" 2>&1 )" || true
## Require BOTH markers BEFORE: if only R-172 were asserted the test would pass
## vacuously when shellcheck is absent (no SC2174 ever emitted), never proving
## the inserted directive suppresses it. shellcheck is a required dep above.
if grep --quiet --fixed-strings 'R-172' <<< "${r172p_before}" \
   && grep --quiet --fixed-strings 'SC2174' <<< "${r172p_before}" \
   && ! grep --quiet --extended-regexp 'R-172|SC2174' <<< "${r172p_after}" ; then
   note_pass "gate parity: --parents atomic form clears R-172 and SC2174 after the fixer"
else
   note_fail "R-172 --parents gate parity broken (R-172 or SC2174 survived)"
fi

## --- 9: R-013 split multiple '-o' options onto one 'set' line each ---------
## Only the PURE multi-'-o' shape is a safe single edit; the short-flag shape
## and mixed/commented lines stay a reported R-013 for a human.
r13="${test_dir}/r013.sh"
printf '%b' '#!/bin/bash\nset -o errexit -o nounset -o pipefail\n' >"${r13}"
"${FIX}" "${r13}" >/dev/null 2>&1
if [ "$(grep --count --line-regexp -- 'set -o errexit' "${r13}")" = '1' ] \
   && [ "$(grep --count --line-regexp -- 'set -o nounset' "${r13}")" = '1' ] \
   && [ "$(grep --count --line-regexp -- 'set -o pipefail' "${r13}")" = '1' ] \
   && ! grep --quiet --fixed-strings -- 'set -o errexit -o' "${r13}" ; then
   note_pass "R-013: multi '-o' line split one per line"
else
   note_fail "R-013: multi '-o' split wrong"
fi

r13_snapshot="$(cat -- "${r13}")"
"${FIX}" "${r13}" >/dev/null 2>&1
if [ "$(cat -- "${r13}")" = "${r13_snapshot}" ]; then
   note_pass "R-013: split is idempotent"
else
   note_fail "R-013: second run changed the file"
fi

## Indentation preserved (a set line inside a function body).
r13i="${test_dir}/r013_indent.sh"
printf '%b' '#!/bin/bash\nf() {\n   set -o errexit -o nounset\n}\n' >"${r13i}"
"${FIX}" "${r13i}" >/dev/null 2>&1
if grep --quiet --line-regexp -- '   set -o errexit' "${r13i}" \
   && grep --quiet --line-regexp -- '   set -o nounset' "${r13i}" ; then
   note_pass "R-013: indentation preserved on split"
else
   note_fail "R-013: indentation not preserved"
fi

## '+o' toggle sign preserved.
r13p="${test_dir}/r013_plus.sh"
printf '%b' '#!/bin/bash\nset -o errexit +o history\n' >"${r13p}"
"${FIX}" "${r13p}" >/dev/null 2>&1
if grep --quiet --line-regexp -- 'set -o errexit' "${r13p}" \
   && grep --quiet --line-regexp -- 'set +o history' "${r13p}" ; then
   note_pass "R-013: '+o' toggle sign preserved"
else
   note_fail "R-013: '+o' sign lost"
fi

## NOT touched: single-option, short-flag bundle, trailing comment -- each is
## already fine or left for the gate (not a safe single edit here).
r13n="${test_dir}/r013_untouched.sh"
printf '%b' '#!/bin/bash\nset -o errexit\nset -eu\nset -o errexit -o nounset # keep\n' >"${r13n}"
r13n_before="$(cat -- "${r13n}")"
"${FIX}" "${r13n}" >/dev/null 2>&1
if [ "$(cat -- "${r13n}")" = "${r13n_before}" ]; then
   note_pass "R-013: single-option, short-flag, and commented lines left untouched"
else
   note_fail "R-013: touched a line outside the pure multi-'-o' shape"
fi

## Waiver: 'allow-short-set' suppresses the split, lockstep with the gate.
r13w="${test_dir}/r013_waived.sh"
printf '%b' '#!/bin/bash\n## style-ok: allow-short-set\nset -o errexit -o nounset\n' >"${r13w}"
r13w_before="$(cat -- "${r13w}")"
"${FIX}" "${r13w}" >/dev/null 2>&1
if [ "$(cat -- "${r13w}")" = "${r13w_before}" ]; then
   note_pass "R-013: allow-short-set waiver suppresses the split"
else
   note_fail "R-013: waiver not honored"
fi

## Gate parity: a file FAILING pre-push-static R-013 PASSES after the fixer.
printf '%b' '#!/bin/bash\nset -o errexit -o nounset -o pipefail\n' >"${repo}/r013gate.sh"
git -C "${repo}" -c core.hooksPath=/dev/null add --all
git -C "${repo}" -c core.hooksPath=/dev/null \
   -c user.name=test -c user.email=test@example.com \
   commit --quiet --message "r013 dirty"
r13_gate_before="$( cd -- "${repo}" && "${GATE}" "${base_sha}" 2>&1 )" || true
"${FIX}" "${repo}/r013gate.sh" >/dev/null 2>&1
git -C "${repo}" -c core.hooksPath=/dev/null add --all
git -C "${repo}" -c core.hooksPath=/dev/null \
   -c user.name=test -c user.email=test@example.com \
   commit --quiet --message "r013 fixed"
r13_gate_after="$( cd -- "${repo}" && "${GATE}" "${base_sha}" 2>&1 )" || true
if grep --quiet --fixed-strings 'R-013' <<< "${r13_gate_before}" \
   && ! grep --quiet --fixed-strings 'R-013' <<< "${r13_gate_after}" ; then
   note_pass "gate parity: R-013 failed before the fixer, clean after"
else
   note_fail "R-013 gate parity broken"
fi

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "pre-push-fix: at least one canary FAILED." >&2
   exit 1
fi
printf '%s\n' "pre-push-fix: all canaries passed."
exit 0
