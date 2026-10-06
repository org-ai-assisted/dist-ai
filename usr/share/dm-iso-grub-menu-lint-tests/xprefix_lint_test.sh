#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Canaries for the shared GRUB x-prefix lint
## (usr/share/dist-ai-tests-common/grub-xprefix-lint).
##
## Drives the REAL checker (no reimplementation) against fixture grub-config
## snippets and asserts its exit code:
##   0 clean, 1 mismatch, 2 not a readable regular file.
##
## Each fixture is test INPUT; the code under test is the checker. The three
## cases the lint regressions guard against:
##   #1 an empty-string compare [ "x${VAR}" = "" ] / = '' is a mismatch
##      (the always-"x" LHS can never be empty) -- MUST be flagged.
##   #2 a correct single-quoted idiom = 'xefi' must NOT be a false positive.
##   #3 a non-regular / unreadable input (directory, FIFO) MUST fail loudly
##      (rc 2), never pass as a clean empty scan.

## Every single-quoted ${VAR} below is DELIBERATE: the fixtures are literal
## grub-config text handed to the checker, not shell to expand here.
# shellcheck disable=SC2016

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp

script_dir="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")"
if [ -x "${script_dir}/../dist-ai-tests-common/grub-xprefix-lint" ]; then
   checker="${script_dir}/../dist-ai-tests-common/grub-xprefix-lint"
else
   checker='/usr/share/dist-ai-tests-common/grub-xprefix-lint'
fi
if [ ! -x "${checker}" ]; then
   printf '%s\n' "FATAL: grub-xprefix-lint checker not found at '${checker}'" >&2
   exit 1
fi

work_dir="$(mktemp --directory -- "${TMP}/xprefix-lint-canary.XXXXXX")"

## Reached only through the EXIT trap below, which shellcheck does not connect
## to this definition.
# shellcheck disable=SC2317
cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}
trap cleanup_handler EXIT

pass=0
fail=0

## Write $2 as a single-line fixture $1, then assert the checker's exit code is
## $3. $2 is single-quoted at the call site so a `${VAR}` in the snippet stays
## literal grub-config text, not a shell expansion here.
assert_rc() {
   local name="$1" content="$2" expected="$3" target rc=0
   target="${work_dir}/${name}"
   printf '%s\n' "${content}" >"${target}"
   "${checker}" "${target}" >/dev/null 2>&1 || rc=$?
   if [ "${rc}" -eq "${expected}" ]; then
      printf 'PASS  %s (rc=%s)\n' "${name}" "${rc}"
      pass=$(( pass + 1 ))
   else
      printf 'FAIL  %s (rc=%s, expected %s)\n' "${name}" "${rc}" "${expected}"
      fail=$(( fail + 1 ))
   fi
}

## Assert the checker's exit code on an existing path (non-regular inputs).
assert_rc_path() {
   local name="$1" target="$2" expected="$3" rc=0
   "${checker}" "${target}" >/dev/null 2>&1 || rc=$?
   if [ "${rc}" -eq "${expected}" ]; then
      printf 'PASS  %s (rc=%s)\n' "${name}" "${rc}"
      pass=$(( pass + 1 ))
   else
      printf 'FAIL  %s (rc=%s, expected %s)\n' "${name}" "${rc}" "${expected}"
      fail=$(( fail + 1 ))
   fi
}

## --- positive control: a real double-quoted mismatch is flagged (rc 1) ------
assert_rc mismatch_double.cfg \
   '   if [ "x${grub_platform}" = "efi" ]; then' 1

## --- #1 false negative: empty-string compares MUST be flagged (rc 1) --------
assert_rc empty_double.cfg \
   '   if [ "x${v}" = "" ]; then' 1
assert_rc empty_single.cfg \
   '   if [ "x${v}" = '\'''\'' ]; then' 1
assert_rc neq_empty_double.cfg \
   '   if [ "x${v}" != "" ]; then' 1

## --- #2 false positive: correct single-quoted idiom must NOT be flagged -----
assert_rc correct_single.cfg \
   '   if [ "x${grub_platform}" = '\''xefi'\'' ]; then' 0

## --- controls: correct idioms + a comment documenting the bug (rc 0) --------
assert_rc correct_double.cfg \
   '   if [ "x${grub_platform}" = "xefi" ]; then' 0
assert_rc correct_unquoted.cfg \
   '   if [ "x${v}" = xefi ]; then' 0
assert_rc comment_doc.cfg \
   '   ## documents the bug: [ "x${v}" = "efi" ] -- always false' 0

## --- regression: valid comparisons the fix must NOT false-flag (rc 0) -------
## A quote-concatenation ""xfoo is the single word 'xfoo', not an empty literal.
assert_rc concat_not_empty.cfg \
   '   if [ "x${v}" = ""xfoo ]; then' 0
## A RHS that is itself a variable is not a literal (it can expand to anything).
assert_rc var_rhs_double.cfg \
   '   if [ "x${a}" = "${b}" ]; then' 0
assert_rc var_rhs_xvar.cfg \
   '   if [ "x${a}" = "x${b}" ]; then' 0
assert_rc var_rhs_bare.cfg \
   '   if [ "x${v}" = $b ]; then' 0

## --- a tab between [ and the test IS linted (context gate accepts any ws) ----
tab_fixture=$'   if [\t"x${v}" = "efi" ]; then'
printf '%s\n' "${tab_fixture}" >"${work_dir}/tab_after_bracket.cfg"
assert_rc_path tab_after_bracket "${work_dir}/tab_after_bracket.cfg" 1

## --- #3 silent-green: a non-regular input MUST fail loudly (rc 2) -----------
mkdir -- "${work_dir}/a_directory.cfg"
assert_rc_path directory_input "${work_dir}/a_directory.cfg" 2
mkfifo -- "${work_dir}/a_fifo.cfg"
assert_rc_path fifo_input "${work_dir}/a_fifo.cfg" 2

printf '%s\n' ""
printf '%s\n' "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
