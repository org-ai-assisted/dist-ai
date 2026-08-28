#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for pre-push-static's '--staged': the gate must judge the
## STAGED BLOB (the index -- exactly what a commit would record), NOT the working
## tree, which can diverge after staging.
##
## WHY IT EXISTS: --staged built each file's context from the working tree on
## disk. So a violation could be STAGED while the working copy was overwritten
## clean -- the gate read the clean disk file, said 'all passed', and let the bad
## blob through (a staged private key / broken shell hidden from the gate). The
## mirror error also bit: an edit made to the working tree AFTER staging a clean
## blob was reported against a commit that would not contain it. Both are fixed
## by reading the blob via 'git cat-file'.
##
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp

## Resolve the gate RELATIVE to this test file (usr/share/<suite>/ -> usr/bin/),
## so a developer editing the in-tree gate tests it and not the packaged copy.
gate_test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
GATE="${gate_test_dir}/../../bin/dist-ai-style"
if [ ! -x "${GATE}" ]; then
   GATE='/usr/bin/dist-ai-style'
fi
if [ ! -x "${GATE}" ]; then
   printf '%s\n' "FATAL: no dist-ai-style to test" >&2
   exit 1
fi

test_dir="$(mktemp --directory -- "${TMP}/pre-push-static-staged-blob.XXXXXX")"
test_cleanup_handler() {
   safe-rm --recursive --force -- "${test_dir}"
}
trap test_cleanup_handler EXIT

pass_count=0
fail_count=0
record() {
   local verdict description
   verdict="$1"
   description="$2"
   if [ "${verdict}" = PASS ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${description}"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: ${description}"
   fi
}

repo="${test_dir}/repo"
mkdir --parents -- "${repo}/usr/bin"
git -c init.defaultBranch=master -c core.hooksPath=/dev/null init --quiet -- "${repo}"
git -C "${repo}" -c core.hooksPath=/dev/null \
   -c user.name=test -c user.email=test@example.com \
   commit --quiet --allow-empty --message 'base'

## Bodies are ASSEMBLED (never spelled literally) so this file does not trip the
## very rules it stages, and no waiver is needed that could hide a real hit.
print_verb='pr''intf'
fixed_format="'%s\\n'"
loose_format="'value: %s\\n'"

## clean_body FILE: strict-mode block, braced expansion, fixed printf format.
clean_body() {
   {
      printf '%s\n' '#!/bin/bash' ''
      printf '%s\n' 'set -o errexit' 'set -o nounset' 'set -o pipefail' \
         'set -o errtrace' 'shopt -s inherit_errexit' 'shopt -s shift_verbose' \
         'export LC_ALL=C' ''
      printf '%s\n' 'value="ok"' "${print_verb} ${fixed_format} \"\${value}\""
   } >"$1"
   chmod 0755 -- "$1"
}

## bad_body FILE: no strict-mode block, unbraced expansion, non-fixed format.
bad_body() {
   {
      printf '%s\n' '#!/bin/bash' ''
      printf '%s\n' 'value="bad"' "${print_verb} ${loose_format} \$value"
   } >"$1"
   chmod 0755 -- "$1"
}

target="${repo}/usr/bin/prog"

## Case 1 -- the security case: a VIOLATING blob is staged, then the working copy
## is overwritten CLEAN. The gate must judge the staged (bad) blob and FAIL.
## Reading the clean working tree would let the bad blob through (exit 0).
bad_body "${target}"
git -C "${repo}" -c core.hooksPath=/dev/null add -- usr/bin/prog
clean_body "${target}"
c1_rc=0
c1_out="$( cd -- "${repo}" && "${GATE}" --check --staged 2>&1 )" || c1_rc=$?
if [ "${c1_rc}" -ne 0 ] \
   && grep --quiet --fixed-strings 'usr/bin/prog' <<< "${c1_out}"; then
   record PASS 'staged violation is caught though the working copy was overwritten clean'
else
   record FAIL "staged violation was hidden by a clean working copy (rc=${c1_rc})"
   printf '%s\n' "  output: $(printf '%s' "${c1_out}" | tr '\n' '|' | head -c 300)"
fi

## Case 2 -- the mirror: a CLEAN blob is staged, then the working copy is
## overwritten VIOLATING. The gate must judge the staged (clean) blob and PASS.
## Reading the dirty working tree would fail on an edit not in the commit.
clean_body "${target}"
git -C "${repo}" -c core.hooksPath=/dev/null add -- usr/bin/prog
bad_body "${target}"
c2_rc=0
c2_out="$( cd -- "${repo}" && "${GATE}" --check --staged 2>&1 )" || c2_rc=$?
if [ "${c2_rc}" -eq 0 ]; then
   record PASS 'staged clean blob passes though the working copy was overwritten violating'
else
   record FAIL "a working-tree edit tripped a check of the clean staged blob (rc=${c2_rc})"
   printf '%s\n' "  output: $(printf '%s' "${c2_out}" | tr '\n' '|' | head -c 300)"
fi

## A working tree diverged from the staged blob draws an informational NOTE, not
## a FAIL -- so a clean pass is not silently a check of stale bytes.
if grep --quiet --fixed-strings 'the gate judged the staged blob' <<< "${c2_out}"; then
   record PASS 'a diverged working tree draws the staged-blob skew note'
else
   record FAIL 'the staged-blob skew note was missing on a diverged working tree'
   printf '%s\n' "  output: $(printf '%s' "${c2_out}" | tr '\n' '|' | head -c 300)"
fi

## The same object-vs-working-tree rule for --range, the mode dm-preflight uses to
## gate a PUSH ('dist-ai-style --check --range BASE'). The range judges the HEAD
## blob (the pushed tip), so a violation COMMITTED at HEAD but reverted in the
## working copy (unstaged) must still FAIL -- else the push carries it unseen and
## the only signal is a NOTE dm-preflight discards.
gc() {
   git -C "${repo}" -c core.hooksPath=/dev/null \
      -c user.name=ci-test -c user.email=ci-test@example.com "$@"
}

## Case 3 -- violation at HEAD, working copy reverted clean: --range must FAIL.
clean_body "${target}"
gc add -- usr/bin/prog
gc commit --quiet --message clean-base
range_base="$(git -C "${repo}" rev-parse HEAD)"
bad_body "${target}"
gc add -- usr/bin/prog
gc commit --quiet --message bad-head
clean_body "${target}"   ## revert the working copy clean, do NOT commit
c3_rc=0
c3_out="$( cd -- "${repo}" && "${GATE}" --check --range "${range_base}" 2>&1 )" || c3_rc=$?
if [ "${c3_rc}" -ne 0 ] \
   && grep --quiet --fixed-strings 'usr/bin/prog' <<< "${c3_out}"; then
   record PASS '--range catches a HEAD violation though the working copy was reverted clean'
else
   record FAIL "--range missed a HEAD violation hidden by a clean working copy (rc=${c3_rc})"
   printf '%s\n' "  output: $(printf '%s' "${c3_out}" | tr '\n' '|' | head -c 300)"
fi
if grep --quiet --fixed-strings 'the gate judged the HEAD blob' <<< "${c3_out}"; then
   record PASS 'a diverged working tree draws the HEAD-blob skew note in --range'
else
   record FAIL 'the HEAD-blob skew note was missing on a diverged --range working tree'
   printf '%s\n' "  output: $(printf '%s' "${c3_out}" | tr '\n' '|' | head -c 300)"
fi

## Case 4 -- clean at HEAD, working copy edited violating: --range must PASS (the
## edit is not in the pushed tip).
clean_body "${target}"
gc add -- usr/bin/prog
gc commit --quiet --message clean-head
range_base2="$(git -C "${repo}" rev-parse 'HEAD~1')"
bad_body "${target}"   ## dirty the working copy, do NOT commit
c4_rc=0
c4_out="$( cd -- "${repo}" && "${GATE}" --check --range "${range_base2}" 2>&1 )" || c4_rc=$?
if [ "${c4_rc}" -eq 0 ]; then
   record PASS '--range passes a clean HEAD though the working copy was edited violating'
else
   record FAIL "a working-tree edit tripped a --range check of the clean HEAD blob (rc=${c4_rc})"
   printf '%s\n' "  output: $(printf '%s' "${c4_out}" | tr '\n' '|' | head -c 300)"
fi

## Adversarial FILENAMES must not evade the object scan. The blob lookup keys on
## the exact path (whole-listing, no per-file pathspec) and fetches BY SHA, so a
## name colliding with git's ':<stage>:<path>' object grammar ('0:x') or carrying
## pathspec MAGIC (':(exclude)x') is scanned like any other -- reading it as a rev
## spec (cat-file) or a pathspec (ls-tree, which errors and is swallowed) would
## silently drop the file from the gate. Both staged as literal paths.
adv_stage='0:decoy'
bad_body "${repo}/${adv_stage}"
gc add -- ":(literal)${adv_stage}"
c5_rc=0
c5_out="$( cd -- "${repo}" && "${GATE}" --check --staged 2>&1 )" || c5_rc=$?
if [ "${c5_rc}" -ne 0 ] \
   && grep --quiet --fixed-strings "${adv_stage}" <<< "${c5_out}"; then
   record PASS 'a ":<stage>:<path>"-colliding staged filename is still scanned'
else
   record FAIL "a ':<stage>:<path>'-colliding staged filename evaded the gate (rc=${c5_rc})"
   printf '%s\n' "  output: $(printf '%s' "${c5_out}" | tr '\n' '|' | head -c 300)"
fi

adv_range=':(exclude)pwn'
bad_body "${repo}/${adv_range}"
gc add -- ":(literal)${adv_range}"
gc commit --quiet --message adv-range
adv_base="$(git -C "${repo}" rev-parse 'HEAD~1')"
c6_rc=0
c6_out="$( cd -- "${repo}" && "${GATE}" --check --range "${adv_base}" 2>&1 )" || c6_rc=$?
if [ "${c6_rc}" -ne 0 ] \
   && grep --quiet --fixed-strings "${adv_range}" <<< "${c6_out}"; then
   record PASS 'a pathspec-magic committed filename is still scanned (--range)'
else
   record FAIL "a pathspec-magic filename evaded the --range gate (rc=${c6_rc})"
   printf '%s\n' "  output: $(printf '%s' "${c6_out}" | tr '\n' '|' | head -c 300)"
fi

printf '%s\n' ""
printf '%s\n' "pre-push-static object-vs-worktree: ${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
