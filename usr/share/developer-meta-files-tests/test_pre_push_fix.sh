#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Canary regression suite for 'dist-ai-style --fix', the bucket-1 AUTO-FIXER.
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
export LC_ALL=C

tool_test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
STYLE="${tool_test_dir}/../../bin/dist-ai-style"
if [ ! -x "${STYLE}" ]; then
   STYLE='/usr/bin/dist-ai-style'
fi
if [ ! -x "${STYLE}" ]; then
   printf '%s\n' "FATAL: dist-ai-style not found (looked at '${STYLE}')." >&2
   exit 1
fi
## The auto-fixer is 'dist-ai-style --fix'; wrap it so the call sites stay terse.
run_fix() { "${STYLE}" --fix "$@"; }
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
passc=0
note_pass() { printf '%s\n' "PASS: ${1}" ; passc=$(( passc + 1 )) ; }
note_fail() { printf '%s\n' "FAIL: ${1}" >&2 ; fail=$(( fail + 1 )) ; }

## The single exit point: a non-zero 'fail' MUST exit 1. This suite once set
## 'fail' but never read it, so every FAIL reported a green exit -- a silent
## pass. Both messages carry the tally so an unauthorized skip cannot hide.
exit_gate() {
   if [ "${fail}" -ne 0 ]; then
      printf '%s\n' "dist-ai-style --fix: ${passc} pass, ${fail} fail, 0 skip -- FAILURES above." >&2
      exit 1
   fi
   printf '%s\n' "dist-ai-style --fix: ${passc} pass, 0 fail, 0 skip -- all canaries passed."
   exit 0
}

## Self-test the FAIL gate on every run, so it cannot silently regress to the
## old always-exit-0. Child (flag set): force one failure and hit the gate,
## which must exit 1. Parent: re-invoke the child and REFUSE if it exits 0.
if [ -n "${TEST_SELFCHECK_FAIL_GATE:-}" ]; then
   note_fail "self-test: forced failure to exercise the FAIL gate"
   exit_gate
fi
if TEST_SELFCHECK_FAIL_GATE=1 "$0" >/dev/null 2>&1; then
   printf '%s\n' "dist-ai-style --fix: FAIL gate regressed -- a forced failure still exits 0" >&2
   exit 1
fi

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
run_fix "${f}" >/dev/null 2>&1
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
run_fix "${f}" >/dev/null 2>&1
if has_non_ascii "${f}" ; then
   note_pass "non-confusable UTF-8 preserved (fixer only touches known set)"
else
   note_fail "non-confusable UTF-8 was altered -- fixer guessed, must not"
fi

## --- 3: allow-non-ascii waiver suppresses R-001, not whitespace -----------
f="${test_dir}/waived.sh"
printf '%b' '#!/bin/bash\n## style-ok: allow-non-ascii\ny=\342\200\224   \n' >"${f}"
run_fix "${f}" >/dev/null 2>&1
if has_non_ascii "${f}" && ! has_trailing_ws "${f}" ; then
   note_pass "waiver keeps non-ASCII, whitespace still fixed (gate parity)"
else
   note_fail "waiver behavior wrong"
fi

## --- 4: undecodable file skipped, bytes unchanged -------------------------
f="${test_dir}/binary.sh"
printf '%b' '#!/bin/bash\n# \377\376 raw  \n' >"${f}"
before="$(cksum < "${f}")"
run_fix "${f}" >/dev/null 2>&1
if [ "$(cksum < "${f}")" = "${before}" ] ; then
   note_pass "undecodable file left byte-identical"
else
   note_fail "undecodable file was modified"
fi

## --- 5: symlink skipped ---------------------------------------------------
printf '%b' '#!/bin/bash\nx=1  \n' >"${test_dir}/target.sh"
ln -s target.sh "${test_dir}/alias.sh"
run_fix "${test_dir}/alias.sh" >/dev/null 2>&1
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
run_fix --check "${f}" >/dev/null 2>&1 || rc=$?
if [ "${rc}" -eq 1 ] && [ "$(cksum < "${f}")" = "${before}" ] ; then
   note_pass "--check exits 1 on dirty file and writes nothing"
else
   note_fail "--check misbehaved (rc=${rc})"
fi

## --- 7: idempotency -------------------------------------------------------
f="${test_dir}/idem.sh"
printf '%b' '#!/bin/bash\n## \342\200\224   \n' >"${f}"
run_fix "${f}" >/dev/null 2>&1
first="$(cksum < "${f}")"
run_fix "${f}" >/dev/null 2>&1
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
run_fix "${f}" >/dev/null 2>&1
if has_non_ascii "${f}" && grep --quiet --fixed-strings -- ' -- ' "${f}" ; then
   note_pass "smart quotes kept in code, em dash still fixed"
else
   note_fail "smart-quote-in-code handling wrong"
fi
## In a .md file the same smart quotes ARE fixed (quotes are content there).
f="${test_dir}/quotes.md"
printf '%b' 'a \342\200\230hi\342\200\231 b\n' >"${f}"
run_fix "${f}" >/dev/null 2>&1
if ! has_non_ascii "${f}" && grep --quiet --fixed-strings -- "'hi'" "${f}" ; then
   note_pass "smart quotes fixed in markup"
else
   note_fail "smart-quote-in-markup handling wrong"
fi

## --- 7c: no-break space is actually substituted --------------------------
f="${test_dir}/nbsp.sh"
printf '%b' '#!/bin/bash\nx=\302\2401\n' >"${f}"
run_fix "${f}" >/dev/null 2>&1
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
run_fix "${f}" >/dev/null 2>&1
if has_non_ascii "${f}" ; then
   note_pass "waiver honored without whitespace after the colon (gate parity)"
else
   note_fail "waiver grammar not in lockstep with the gate"
fi

## --- 7e: --staged outside a repo is an ERROR, not a false green ----------
nonrepo="${test_dir}/nonrepo"
mkdir --parents -- "${nonrepo}"
rc=0
( cd -- "${nonrepo}" && run_fix --staged >/dev/null 2>&1 ) || rc=$?
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
run_fix "${f}" >/dev/null 2>&1
if [ "$(grep --count --fixed-strings -- '--mode=700' "${f}")" -eq 2 ] \
   && ! grep --quiet --extended-regexp -- '(^|[[:space:]])-m' "${f}" ; then
   note_pass "R-172 short -m upgraded to --mode= (spaced and attached)"
else
   note_fail "R-172 short-mode upgrade wrong"
fi
first="$(cksum < "${f}")"
run_fix "${f}" >/dev/null 2>&1
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
run_fix "${f}" >/dev/null 2>&1
if [ "$(cksum < "${f}")" = "${before}" ] ; then
   note_pass "R-172 leaves the missing-mode form for the gate (not auto-fixed)"
else
   note_fail "R-172 fixer altered a form it must not"
fi

## --- 7h: a bundled '-pm700' is left for the gate (conservative) ------------
f="${test_dir}/mkdirbundle.sh"
printf '%b' '#!/bin/bash\nmkdir -pm700 -- "$TMPDIR"\n' >"${f}"
before="$(cksum < "${f}")"
run_fix "${f}" >/dev/null 2>&1
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
run_fix "${f}" >/dev/null 2>&1
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
run_fix "${f}" >/dev/null 2>&1
if [ "$(grep --count --fixed-strings -- 'disable=SC2174' "${f}")" -eq 1 ] \
   && grep --quiet --fixed-strings -- 'mkdir --parents --mode=700' "${f}" ; then
   note_pass "R-172 inserts one SC2174 disable for --parents --mode (not for plain --mode)"
else
   note_fail "R-172 SC2174 disable insertion wrong"
fi
first="$(cksum < "${f}")"
run_fix "${f}" >/dev/null 2>&1
if [ "$(cksum < "${f}")" = "${first}" ] ; then
   note_pass "R-172 SC2174 disable insertion idempotent (not doubled)"
else
   note_fail "R-172 SC2174 disable insertion not idempotent"
fi

## --- 7l: a mkdir inside a HEREDOC body is never edited (no data corruption) --
## A '$(mkdir --parents -m 700 ...)' in here-document text is real code, so the
## AST yields it -- but the fixer must NOT touch it: inserting the SC2174 comment
## would splice into the here-document DATA. Canary: the old fixer corrupted it.
f="${test_dir}/mkdirheredoc.sh"
printf '%b' '#!/bin/bash\ncat <<EOF\n$(mkdir --parents -m 700 -- "$TMPDIR")\nEOF\n' >"${f}"
before="$(cksum < "${f}")"
run_fix "${f}" >/dev/null 2>&1
if [ "$(cksum < "${f}")" = "${before}" ] \
   && ! grep --quiet --fixed-strings -- 'disable=SC2174' "${f}" ; then
   note_pass "R-172 leaves a mkdir inside a heredoc body untouched (no corruption)"
else
   note_fail "R-172 corrupted a heredoc body (edited a command inside it)"
fi

## --- 7k: the disable is NOT wedged into a '\'-continuation -----------------
## A temp mkdir that continues a '\'-terminated line must not get a comment
## inserted between the two -- that would break the continuation. The fixer
## leaves such a line alone (SC2174 there is a rare human fix).
f="${test_dir}/mkdircont.sh"
# shellcheck disable=SC2174
printf '%b' '#!/bin/bash\ntrue \\\n&& mkdir --parents --mode=700 -- "$TMPDIR"\n' >"${f}"
before="$(cksum < "${f}")"
run_fix "${f}" >/dev/null 2>&1
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
run_fix "${f}" >/dev/null 2>&1
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
run_fix "${f}" >/dev/null 2>&1
if [ "$(cksum < "${f}")" = "${before}" ] ; then
   note_pass "R-172 leaves an -m inside a quoted path / after -- untouched"
else
   note_fail "R-172 rewrote a literal directory name"
fi
## A backtick command substitution is command position -> the mkdir is upgraded.
f="${test_dir}/mkdirbtick.sh"
printf '%b' '#!/bin/bash\nfoo=`mkdir --mode=700 -- "$TMPDIR"`\n' >"${f}"
run_fix "${f}" >/dev/null 2>&1
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
run_fix "${f}" >/dev/null 2>&1
if [ "$(cksum < "${f}")" = "${before}" ] ; then
   note_pass "R-172 honors the allow-mkdir-no-mode waiver (fixer/gate parity)"
else
   note_fail "R-172 rewrote a file that waived the rule"
fi
## The SC2174 skip is exact: 'SC21745' is a different code and must not mask the
## required directive, which is still inserted (as its own whole line).
f="${test_dir}/mkdirsc.sh"
printf '%b' '#!/bin/bash\n# shellcheck disable=SC21745\nmkdir -p --mode=700 -- "$TMPDIR"\n' >"${f}"
run_fix "${f}" >/dev/null 2>&1
if grep --quiet --line-regexp --fixed-strings -- '# shellcheck disable=SC2174' "${f}" ; then
   note_pass "R-172 SC2174 skip is exact (SC21745 does not mask it)"
else
   note_fail "R-172 SC2174 boundary wrong (directive not inserted)"
fi
## An EVEN run of trailing backslashes is an escaped backslash, not a line
## continuation, so the disable IS inserted above the next mkdir.
f="${test_dir}/mkdireven.sh"
printf '%b' '#!/bin/bash\necho \\\\\nmkdir -p --mode=700 -- "$TMPDIR"\n' >"${f}"
run_fix "${f}" >/dev/null 2>&1
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
run_fix "${repo}/doc.md" >/dev/null 2>&1
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
run_fix "${repo}/tmpdir.sh" >/dev/null 2>&1
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
run_fix "${repo}/tmpparents.sh" >/dev/null 2>&1
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

## --- 9: AST fixer reaches files with multi-line constructs -----------------
## The former regex fixer DECLINED any file containing a heredoc / line
## continuation / multi-line string (has_multiline_construct), so a real
## violation there went unfixed and the model corrected it by hand. The AST
## fixer parses the file: a command OUTSIDE a heredoc is fixed, while the same
## token INSIDE the heredoc (data) and inside an array (not a command) is left
## untouched. Also proves command position after a 'VAR=value' assignment prefix.
## The short-quiet grep literal is assembled from variables ('${g} ${iq}') so
## THIS test source carries no 'grep -<q>' cluster of its own for R-161 to flag.
g='grep'
iq='-iq'
f="${test_dir}/heredoc.sh"
printf '%b' "#!/bin/bash\ntimeout 5 sleep 1\nDEBUG=1 ${g} ${iq} foo bar\ncat <<HD\ntimeout 5 sleep 1 stays as heredoc data\nHD\narr=(timeout 5 x)\n" >"${f}"
if grep --quiet --fixed-strings 'timeout --kill-after=5 5 sleep 1' "${f}" ; then
   note_fail "heredoc fixture not dirty -- canary would let a no-op fixer pass"
fi
run_fix "${f}" >/dev/null 2>&1
if grep --quiet --fixed-strings 'timeout --kill-after=5 5 sleep 1' "${f}" \
   && grep --quiet --fixed-strings 'DEBUG=1 grep --ignore-case --quiet foo bar' "${f}" \
   && grep --quiet --fixed-strings 'timeout 5 sleep 1 stays as heredoc data' "${f}" \
   && grep --quiet --fixed-strings 'arr=(timeout 5 x)' "${f}" ; then
   note_pass "AST fixer: heredoc file fixed; heredoc body + array left as data; assignment prefix handled"
else
   note_fail "AST structural fix wrong on a multi-line file"
fi

## --- 9b: gate parity CANARY -- a heredoc file failed R-200 before, clean after
## The headline win of the AST port. The regex fixer declined this file (it has
## a heredoc), so R-200 SURVIVED it -- this assertion FAILS on the old fixer and
## passes on the AST one.
printf '%b' '#!/bin/bash\ntimeout 5 sleep 1\ncat <<HD\nx\nHD\n' >"${repo}/heredoc_to.sh"
git -C "${repo}" -c core.hooksPath=/dev/null add --all
git -C "${repo}" -c core.hooksPath=/dev/null \
   -c user.name=test -c user.email=test@example.com \
   commit --quiet --message "heredoc r200 dirty"
hd_before="$( cd -- "${repo}" && "${GATE}" "${base_sha}" 2>&1 )" || true
run_fix "${repo}/heredoc_to.sh" >/dev/null 2>&1
git -C "${repo}" -c core.hooksPath=/dev/null add --all
git -C "${repo}" -c core.hooksPath=/dev/null \
   -c user.name=test -c user.email=test@example.com \
   commit --quiet --message "heredoc r200 fixed"
hd_after="$( cd -- "${repo}" && "${GATE}" "${base_sha}" 2>&1 )" || true
if grep --quiet --fixed-strings 'R-200' <<< "${hd_before}" \
   && ! grep --quiet --fixed-strings 'R-200' <<< "${hd_after}" ; then
   note_pass "gate parity: heredoc file failed R-200 before the fixer, clean after (AST port canary)"
else
   note_fail "AST port canary broken: R-200 not cleared on a heredoc file"
fi

## --- 9d: SC2174 insertion uses BYTE offsets (non-ASCII before the mkdir) -----
## Regression: a non-ASCII char earlier in the file must not shift the inserted
## disable into the previous line (str char-index vs shfmt byte-offset mismatch).
f="${test_dir}/nonascii.sh"
printf '%b' '#!/bin/bash\n## caf\303\251 padding comment here\nmkdir --parents -m 700 -- "$TMPDIR"\n' >"${f}"
run_fix "${f}" >/dev/null 2>&1
if grep --line-regexp --quiet -- '# shellcheck disable=SC2174' "${f}" \
   && grep --quiet --fixed-strings -- 'mkdir --parents --mode=700 -- "$TMPDIR"' "${f}" \
   && grep --quiet --fixed-strings -- 'padding comment here' "${f}" ; then
   note_pass "SC2174 lands on its own line despite non-ASCII above (byte offsets)"
else
   note_fail "SC2174 insertion corrupted by a non-ASCII line above the mkdir"
fi

## --- 9e: space-form '--mode 700 -p' still detects -p and inserts SC2174 -------
f="${test_dir}/spacemode.sh"
printf '%b' '#!/bin/bash\nmkdir --mode 700 -p "$TMPDIR/x"\n' >"${f}"
run_fix "${f}" >/dev/null 2>&1
if grep --line-regexp --quiet -- '# shellcheck disable=SC2174' "${f}" ; then
   note_pass "space-form --mode with -p gets the SC2174 disable (value skipped)"
else
   note_fail "space-form '--mode 700 -p' missed -p, no SC2174 inserted"
fi

## --- 9c: a file shfmt cannot parse is DECLINED structurally, not crashed ----
## A syntax error must not abort the fixer; the text transforms still run and the
## structural rules are left to the gate (which also runs 'bash -n').
f="${test_dir}/broken.sh"
printf '%b' '#!/bin/bash\nif [ 1 ; then\ntimeout 5 sleep 1\n## a \342\200\224 b   \n' >"${f}"
rc=0
run_fix "${f}" >/dev/null 2>&1 || rc=$?
if [ "${rc}" -eq 0 ] \
   && ! has_non_ascii "${f}" \
   && ! has_trailing_ws "${f}" \
   && grep --quiet --fixed-strings 'timeout 5 sleep 1' "${f}" ; then
   note_pass "unparseable file: text transforms applied, structural declined, no crash"
else
   note_fail "unparseable file mishandled (rc=${rc})"
fi

## --- 8: a TRAILING no-break space is fixed in ONE pass ---------------------
## Confusable-substitution turns the NBSP into an ASCII space; the strip must
## then see it in the SAME fix pass. Canary: FAILs when the text rules share
## one pre-substitution snapshot (a residual trailing space survives).
f="${test_dir}/nbsp-trail.sh"
printf '%b' '#!/bin/bash\nx=1\302\240\n' >"${f}"
run_fix "${f}" >/dev/null 2>&1
if ! has_non_ascii "${f}" && ! has_trailing_ws "${f}" ; then
   note_pass "trailing no-break space fixed in one pass (no residual space)"
else
   note_fail "trailing no-break space left a residual (needed a second pass)"
fi

## --- 9: trailing blanks before a LONE CR (old-Mac EOL) are stripped --------
## The strip must peel blanks before a bare '\r' with no LF, preserving the CR.
f="${test_dir}/crtrail.sh"
printf '%b' '#!/bin/bash\nfoo  \r' >"${f}"
printf '%b' '#!/bin/bash\nfoo\r' >"${test_dir}/crtrail.expect"
run_fix "${f}" >/dev/null 2>&1
if cmp -s "${f}" "${test_dir}/crtrail.expect" ; then
   note_pass "trailing blanks before a lone CR stripped, CR preserved"
else
   note_fail "CR-only trailing whitespace not stripped"
fi

## --- 10: R-172 does NOT splice across an intervening redirection -----------
## A redirection between '-m' and its mode value lives on the Stmt, not Args; a
## span from '-m' to the mode word would DELETE it, so the fixer declines and
## leaves the (rare) shape byte-identical for the gate.
f="${test_dir}/mkdir-redir.sh"
printf '%b' '#!/bin/bash\nmkdir -m >/dev/null 700 -- "$TMPDIR"\n' >"${f}"
before="$(cksum < "${f}")"
run_fix "${f}" >/dev/null 2>&1
if [ "$(cksum < "${f}")" = "${before}" ] ; then
   note_pass "R-172 leaves a -m/value pair split by a redirection untouched"
else
   note_fail "R-172 spliced across a redirection (data loss)"
fi

## --- 11: R-062 drops the '--' the denylisted tool rejects ------------------
## 'git check-ref-format -- <ref>' errors on the literal '--'; the fixer removes
## it (with one leading space) so the call is clean. Canary: dirty before, and
## the exact fixed text after.
f="${test_dir}/dashdash.sh"
printf '%b' '#!/bin/bash\ngit check-ref-format -- refs/heads/x\n' >"${f}"
run_fix "${f}" >/dev/null 2>&1
if grep --quiet --fixed-strings -- 'git check-ref-format refs/heads/x' "${f}" \
   && ! grep --quiet --fixed-strings -- 'check-ref-format --' "${f}" ; then
   note_pass "R-062 dropped the '--' passed to a denylisted tool"
else
   note_fail "R-062 did not drop the rejecting '--'"
fi

exit_gate
