#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## strings.bsh: read_integer_file, which reads a number back out of a state
## file.
##
## THE BUG: the read went through 'stcat -- "${target_file}"'. stcat takes
## EVERY argument as a path, so it read the '--' separator itself as a
## filename and died with FileNotFoundError. read_integer_file then reported
## "Cannot stcat target file" for a file that was present and readable, and
## four of tb-updater's e2e scenarios failed on it -- all of them the ones
## that read a cached signature timestamp back.
##
## R-062 is why it was added: the separator is right for tools that accept
## one. It is a bug for tools that do not, which is the rule's negative half.
## pre-push-static now denylists 'stcat --'; this test pins the runtime side.
##
## Tests the INSTALLED library by default; a self-relative source would pass
## against a stale install, which is the failure mode this suite exists to
## catch. HELPER_SCRIPTS_REPO points it at a checkout explicitly, which is what
## the suite runner wires in CI where nothing is installed.
##
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

[ -v TMP ] || TMP=/tmp
[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   strings_bsh_path="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts/strings.bsh"
   stcat_bin="${HELPER_SCRIPTS_REPO}/usr/bin/stcat"
else
   strings_bsh_path='/usr/libexec/helper-scripts/strings.bsh'
   stcat_bin='/usr/bin/stcat'
fi

if [ ! -r "${strings_bsh_path}" ]; then
   printf '%s\n' "SKIP: strings.bsh not readable at '${strings_bsh_path}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a checkout, or install helper-scripts" >&2
   exit 77
fi

if [ ! -x "${stcat_bin}" ]; then
   printf '%s\n' "SKIP: stcat not executable at '${stcat_bin}'" >&2
   printf '%s\n' "without it the read path under test cannot run at all" >&2
   exit 77
fi

## The library calls 'stcat' by NAME, so the checkout's copy has to be the one
## PATH resolves -- otherwise a checkout run silently exercises the INSTALLED
## stcat and says nothing about the code under test.
PATH="$(dirname -- "${stcat_bin}"):${PATH}"
export PATH

## shellcheck resolves the file statically from dist-ai's own tree, which has
## no helper-scripts copy, so there is nothing to point 'source=' at.
# shellcheck disable=SC1090,SC1091
source "${strings_bsh_path}"

if [ ! "$(type -t read_integer_file)" = 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${strings_bsh_path}' defined no 'read_integer_file'" >&2
   printf '%s\n' "every case below would then fail on 'command not found', not on behaviour" >&2
   exit 1
fi

test_dir="$(mktemp --directory -- "${TMP}/read-integer-file-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${test_dir}"
}

trap test_cleanup_handler EXIT

pass_count=0
fail_count=0

check_reads() {
   local description contents expected actual rc

   description="$1"
   contents="$2"
   expected="$3"

   printf '%s\n' "${contents}" >"${test_dir}/value"
   rc=0
   actual="$(read_integer_file "${test_dir}/value" 1 4294967295 2>/dev/null)" || rc=$?
   if [ "${rc}" -ne 0 ]; then
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: ${description} -- read_integer_file returned ${rc}"
      return 0
   fi
   if [ ! "${actual}" = "${expected}" ]; then
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: ${description} -- expected ${expected}, got ${actual}"
      return 0
   fi
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: ${description}"
}

check_rejects() {
   local description contents rc

   description="$1"
   contents="$2"

   printf '%s\n' "${contents}" >"${test_dir}/value"
   rc=0
   read_integer_file "${test_dir}/value" 1 4294967295 >/dev/null 2>&1 || rc=$?
   if [ "${rc}" -eq 0 ]; then
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: ${description} -- accepted"
      return 0
   fi
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: ${description}"
}

## The case that broke: an ordinary unix timestamp, the shape tb-updater
## stores in last_used_gpg_bash_lib_output_signed_on_unixtime.
check_reads 'a unix timestamp is read back' '1786185710' '1786185710'
check_reads 'the lower bound itself is accepted' '1' '1'
check_reads 'the upper bound itself is accepted' '4294967295' '4294967295'

check_rejects 'a non-numeric value' 'not-a-number'
check_rejects 'a value below the lower bound' '0'
check_rejects 'a value above the upper bound' '4294967296'

## An absent file must fail rather than return an empty string that a caller
## would then use in arithmetic.
rc=0
read_integer_file "${test_dir}/absent" 1 4294967295 >/dev/null 2>&1 || rc=$?
if [ "${rc}" -eq 0 ]; then
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: an absent file was accepted"
else
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: an absent file is rejected"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
