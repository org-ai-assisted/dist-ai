#!/bin/bash

## Copyright (C) 2025 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## has.sh: 'has' is the R-090 replacement for 'command -v', so it has to
## succeed for everything 'command -v' succeeds for -- including shell
## builtins, where 'command -v' prints a bare word instead of a path.
##
## THE BUG: 'command -v printf' prints 'printf', and testing that with '-x'
## resolved it as a RELATIVE path in the current directory. So 'has printf'
## answered yes or no depending on what happened to sit in the cwd.
##
## Sources the INSTALLED has.sh by default, not a copy resolved relative to
## this file. A self-relative source validates the checkout and passes even
## when the deployed copy is stale, which is exactly the failure it must be
## able to catch -- it reported 7/7 against a broken install once already.
## HELPER_SCRIPTS_REPO points it at a checkout explicitly, which is what the
## suite runner wires in CI where nothing is installed.
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
[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   has_sh_path="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts/has.sh"
else
   has_sh_path='/usr/libexec/helper-scripts/has.sh'
fi

if [ ! -r "${has_sh_path}" ]; then
   printf '%s\n' "FATAL: has.sh not readable at '${has_sh_path}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a checkout, or install helper-scripts" >&2
   exit 1
fi

## shellcheck resolves the file statically from dist-ai's own tree, which has
## no helper-scripts copy, so there is nothing to point 'source=' at.
# shellcheck disable=SC1090,SC1091
source "${has_sh_path}"

if [ ! "$(type -t has)" = 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${has_sh_path}' defined no 'has' function" >&2
   printf '%s\n' "every case below would then fail on 'command not found', not on behaviour" >&2
   exit 1
fi

## The cwd decides the answer in the broken version, so run from a directory
## that is known to contain no same-named file.
work_dir="$(mktemp --directory -- "${TMP}/has-builtin-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}

trap test_cleanup_handler EXIT

cd -- "${work_dir}"

pass_count=0
fail_count=0

check_has_succeeds() {
   local label

   label="$1"
   shift

   if has "$@"; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${label}"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: ${label}: 'has $*' returned non-zero"
   fi
}

check_has_fails() {
   local label

   label="$1"
   shift

   if has "$@"; then
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: ${label}: 'has $*' unexpectedly returned zero"
   else
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${label}"
   fi
}

check_has_succeeds 'builtin: printf' printf
check_has_succeeds 'builtin: cd' cd
check_has_succeeds 'builtin: test' test

## An external command still resolves to an absolute path and is still checked.
check_has_succeeds 'external: cat' cat

## Several names at once, mixing a builtin and an external command.
check_has_succeeds 'mixed builtin and external' printf cat

## A name that does not exist anywhere must still fail.
check_has_fails 'absent command' this-command-does-not-exist-12345

## A builtin must not rescue an absent sibling in the same call.
check_has_fails 'absent, mixed with a builtin' printf this-command-does-not-exist-12345

## A file named like a builtin in the cwd must not change the answer either --
## the '-x' resolution the fix removed is exactly what this would exploit.
printf '%s\n' '#!/bin/bash' >"${work_dir}/printf"
chmod 0755 -- "${work_dir}/printf"
check_has_succeeds 'builtin with a same-named file in the cwd' printf
safe-rm --force -- "${work_dir}/printf"

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
