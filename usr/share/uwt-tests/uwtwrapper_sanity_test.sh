#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## uwtwrapper sanity_tests_general: the pre-dispatch error branches that reject a
## malformed invocation before any torification exec happens. Exercised:
##   - empty uwtwrapper_parent -> exit 255, "not supposed to run manually";
##   - ${parent}.anondist-orig MISSING and no command-not-found on PATH -> exit 1,
##     "does not exist" + an apt install hint;
##   - ${parent}.anondist-orig MISSING but command-not-found present -> exec
##     'command-not-found --ignore-installed <app>';
##   - ${parent}.anondist-orig present but NOT executable -> exit 1,
##     "is not executable".
##
## Method: drive the REAL uwtwrapper under a hermetic `env -i` with a PATH built
## from a private tool dir (symlinks to the coreutils the wrapper calls) so that
## command-not-found's presence is controlled exactly: absent for the "does not
## exist" branch, a recording stub for the exec branch. nested_protection runs
## BEFORE sanity_tests_general, so uwtwrapper_counter is left unset (-> 1, well
## under uwtwrapper_max) and never trips the recursion guard.
##
## Targets the installed package by default; set UWT_REPO to test a checkout
## (then HELPER_SCRIPTS_PATH must point at a helper-scripts checkout so the
## wrapper can source strings.bsh / has.bsh). A missing subject or helper
## library is a REQUIRED-dependency environment bug -> exit 1 (FATAL), never a
## skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v UWT_REPO ] || UWT_REPO=""
if [ -n "${UWT_REPO}" ]; then
   libexec_dir="${UWT_REPO}/usr/libexec/uwt"
else
   libexec_dir='/usr/libexec/uwt'
fi
uwtwrapper="${libexec_dir}/uwtwrapper"

[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""
strings_bsh="${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/strings.bsh"

if [ ! -r "${uwtwrapper}" ]; then
   printf '%s\n' "FATAL: uwtwrapper not readable at '${uwtwrapper}'" >&2
   printf '%s\n' "set UWT_REPO to a uwt checkout, or install uwt" >&2
   exit 1
fi
if [ ! -r "${strings_bsh}" ]; then
   printf '%s\n' "FATAL: strings.bsh not readable at '${strings_bsh}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_PATH to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi

## uwtwrapper sources /etc/uwt.d/*.conf and /usr/local/etc/uwt.d/*.conf from
## HARDCODED paths (not env-overridable, by security design). A host conf could
## rewrite uwtwrapper_parent or alter dispatch, so refuse to run when any exists
## rather than report a non-hermetic result.
for host_conf in /etc/uwt.d/*.conf /usr/local/etc/uwt.d/*.conf; do
   [ -e "${host_conf}" ] || continue
   printf '%s\n' "FATAL: host uwt config present ('${host_conf}'); test is not hermetic against it" >&2
   exit 1
done

test_dir="$(mktemp --directory)"
cleanup_handler() {
   ## '|| true': a cleanup failure must not clobber the script's real exit code.
   safe-rm -r -f -- "${test_dir}" || true
}
trap cleanup_handler EXIT

## Private tool dir: symlinks to the only external commands the wrapper runs
## before sanity_tests_general (wc for strings.bsh's source-time self-test;
## basename for SCRIPTNAME; readlink for the alternatives lookup). Keeping it the
## sole PATH entry (no /usr/bin) is what makes command-not-found's presence
## controllable per case.
tool_dir="${test_dir}/tools"
mkdir -p -- "${tool_dir}"
for tool in wc basename readlink; do
   tool_path="$(type -P "${tool}")"
   if [ -z "${tool_path}" ]; then
      printf '%s\n' "FATAL: required tool '${tool}' not found on PATH" >&2
      exit 1
   fi
   ln -s -- "${tool_path}" "${tool_dir}/${tool}"
done

## command-not-found stub: record its argv (CNF_MARK) then exit 0. Placed in its
## own dir so it is on PATH only for the case that wants it. Literal shell
## written to a file; its $-expressions expand when the stub runs, not here.
cnf_dir="${test_dir}/cnf"
mkdir -p -- "${cnf_dir}"
# shellcheck disable=SC2016
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'printf "%s\n" "$*" >> "${CNF_MARK}"'
   printf '%s\n' 'exit 0'
} > "${cnf_dir}/command-not-found"
chmod 0755 -- "${cnf_dir}/command-not-found"

pass=0
fail=0
check_eq() {
   local label="$1" got="$2" want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')"
      fail=$((fail + 1))
   fi
}
## Substring match via [[ ]], not grep (R-161).
check_substr() {
   local label="$1" haystack="$2" needle="$3"
   if [[ "${haystack}" == *"${needle}"* ]]; then
      printf '%s\n' "PASS: ${label}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (missing '${needle}')"
      fail=$((fail + 1))
   fi
}

## Run the REAL uwtwrapper under env -i and capture its combined output + exit
## code. $1 is the PATH to use; the rest are extra NAME=VALUE env pairs. Sets the
## globals 'rc' and 'out'. '|| rc=$?' keeps errexit from aborting on the
## wrapper's intended non-zero exits.
rc=0
out=""
run_wrapper() {
   local use_path="$1"; shift
   rc=0
   out="$(env -i \
      PATH="${use_path}" \
      HOME="${test_dir}" \
      HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_PATH}" \
      "$@" "${uwtwrapper}" 2>&1)" || rc=$?
}

## Case 1: empty uwtwrapper_parent -> manual-run rejection, exit 255.
run_wrapper "${tool_dir}" uwtwrapper_parent=""
check_eq     "empty parent: exit 255"          "${rc}" "255"
check_substr "empty parent: manual-run message" "${out}" "not supposed to run"

## Case 2: ${parent}.anondist-orig missing, command-not-found NOT on PATH ->
## "does not exist" + apt install hint, exit 1. parent basename is 'noorig'.
run_wrapper "${tool_dir}" uwtwrapper_parent="${test_dir}/noorig"
check_eq     "missing orig, no cnf: exit 1"            "${rc}" "1"
check_substr "missing orig, no cnf: does-not-exist"    "${out}" ".anondist-orig' does not exist"
check_substr "missing orig, no cnf: apt install hint"  "${out}" "sudo apt install noorig"

## Case 3: ${parent}.anondist-orig missing, command-not-found stub on PATH ->
## wrapper execs 'command-not-found --ignore-installed noorig'.
cnf_mark="$(mktemp --tmpdir="${test_dir}")"
run_wrapper "${cnf_dir}:${tool_dir}" uwtwrapper_parent="${test_dir}/noorig" CNF_MARK="${cnf_mark}"
check_eq     "missing orig, cnf present: stub exec'd (exit 0)" "${rc}" "0"
check_substr "missing orig, cnf present: --ignore-installed <app>" "$(cat -- "${cnf_mark}")" "--ignore-installed noorig"

## Case 4: ${parent}.anondist-orig present but NOT executable -> exit 1,
## "is not executable".
noexec_base="${test_dir}/noexec"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'exit 0'
} > "${noexec_base}.anondist-orig"
chmod 000 -- "${noexec_base}.anondist-orig"
run_wrapper "${tool_dir}" uwtwrapper_parent="${noexec_base}"
check_eq     "orig not executable: exit 1"          "${rc}" "1"
check_substr "orig not executable: not-exec message" "${out}" "is not executable"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
