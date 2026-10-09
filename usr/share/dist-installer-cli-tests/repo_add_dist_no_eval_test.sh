#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: repo-add-dist (runs as root) set_default_variable must store a
## value VERBATIM, never parse it as shell code. A value carrying a single quote
## (e.g. an inherited 'codename') must not break out and execute a command.
##
## SUBJECT: the real usr/bin/repo-add-dist; check_variable_name and
## set_default_variable are extracted from the CURRENT script text (no copy).
## The whole script is not run: it requires root and writes /etc/apt.
##
## Canary: on the eval-based code the payload's 'touch' runs and the stored
## value is truncated, so both assertions fail.
##
## Exit: 0 pass | 1 fail | 77 usability-misc checkout absent (target-absent).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

repo="${USABILITY_MISC_REPO:-}"
if [ -z "${repo}" ]; then
   repo="${HOME}/derivative-maker/packages/kicksecure/usability-misc"
fi
subject="${repo}/usr/bin/repo-add-dist"
if [ ! -r "${subject}" ]; then
   printf '%s\n' "SKIP: not readable: '${subject}'" >&2
   printf '%s\n' "set USABILITY_MISC_REPO to a usability-misc checkout." >&2
   ## style-ok: allow-skip: usability-misc is a cross-component subject; absent = target-absent SKIP, --allow-skip governs it
   exit 77
fi

work_dir="$(mktemp --directory)"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${work_dir}" || true
}
trap cleanup EXIT

functions_file="${work_dir}/functions.bash"
sed --quiet \
   --expression='/^check_variable_name() {$/,/^}$/p' \
   --expression='/^set_default_variable() {$/,/^}$/p' \
   -- "${subject}" >| "${functions_file}"

pass=0
fail=0
check() {
   local desc="$1"
   shift
   if "$@"; then
      printf '%s\n' "PASS: ${desc}"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: ${desc}"
      fail=$(( fail + 1 ))
   fi
}

check 'both functions extracted' \
   test "$(grep --count --extended-regexp -- '^(check_variable_name|set_default_variable)\(\) \{$' "${functions_file}")" = 2

marker="${work_dir}/injected"
payload="x'; touch -- '${marker}'; '"

# shellcheck disable=SC1090 # dynamic path: the functions are extracted at runtime
source -- "${functions_file}"

unset -v repo_add_dist_test_var
## Non-fatal: on eval-based code the injected tail errors; the asserts report it.
set_default_variable repo_add_dist_test_var "${payload}" >/dev/null || true
check 'quote payload does not execute' test ! -e "${marker}"
check 'quote payload stored verbatim' test "${repo_add_dist_test_var:-}" = "${payload}"

repo_add_dist_test_preset='keep'
set_default_variable repo_add_dist_test_preset 'other' >/dev/null
check 'pre-set variable kept' test "${repo_add_dist_test_preset}" = 'keep'

refuses_invalid_name() {
   ! set_default_variable 'a;b' 'v' >/dev/null
}
check 'invalid variable name refused' refuses_invalid_name

printf '%s\n' "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
