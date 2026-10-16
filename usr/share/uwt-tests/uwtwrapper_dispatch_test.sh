#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## uwtwrapper dispatch: which exec chain a wrapped command takes.
##
## uwtwrapper's final hand-off prepends `torsocks` (stream isolation) only when
## wrapping is active; otherwise it execs the uwtexec stage bare. The env-driven
## decisions under test:
##   - default (uwtwrapper_global defaults to 1) -> torsocks THEN uwtexec;
##   - uwtwrapper_global=0                        -> bare uwtexec, no torsocks;
##   - UWT_DEV_PASSTHROUGH=1 (empties torsocks)   -> bare uwtexec, no torsocks.
## The config-file-driven branches (per-application uwtwrapper[path]=0, Time
## Privacy, bindp) are NOT exercised here: uwtwrapper reads them only from the
## hardcoded /etc/uwt.d and /usr/local/etc/uwt.d (intentionally not env-
## injectable, so a torification wrapper cannot be pointed at rogue config), so
## they are not hermetically reachable without root-writable config.
##
## Method: drive the REAL uwtwrapper under a hermetic `env -i`. torsocks is a
## PATH stub that records it ran then execs the rest of the chain; the uwtexec
## stage is a recording stub (uwtexec_bin override) that is terminal. So the
## two marker files reveal exactly which chain ran, with no real torsocks,
## uwtexec, Tor or wrapped binary touched.
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

test_dir="$(mktemp --directory)"
cleanup_handler() {
   ## '|| true': a cleanup failure must not clobber the script's real exit code.
   safe-rm -r -f -- "${test_dir}" || true
}
trap cleanup_handler EXIT

bin_dir="${test_dir}/bin"
mkdir -p -- "${bin_dir}"

## torsocks stub: record that it ran (to TORSOCKS_MARK), then exec the rest of
## the chain (the uwtexec stage) so dispatch continues normally. The stub body
## is literal shell written to a file; its $-expressions expand when the stub
## runs, not here.
# shellcheck disable=SC2016
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'printf "%s\n" ran >> "${TORSOCKS_MARK}"'
   printf '%s\n' 'exec "$@"'
} > "${bin_dir}/torsocks"
chmod 0755 -- "${bin_dir}/torsocks"

## uwtexec stage stub (uwtexec_bin override): record its argv (UWTEXEC_MARK),
## terminal. Literal shell written to a file (see SC2016 note above).
uwtexec_stub="${test_dir}/uwtexec_stub"
# shellcheck disable=SC2016
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'printf "%s\n" "$*" >> "${UWTEXEC_MARK}"'
   printf '%s\n' 'exit 0'
} > "${uwtexec_stub}"
chmod 0755 -- "${uwtexec_stub}"

## sanity_tests_general requires ${parent}.anondist-orig to exist and be
## executable (a dummy is fine: the uwtexec_bin stub is terminal, so the real
## target is never exec'd).
app_base="${test_dir}/myapp"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'exit 0'
} > "${app_base}.anondist-orig"
chmod 0755 -- "${app_base}.anondist-orig"

base_path="${bin_dir}:/usr/bin:/bin"

pass=0
fail=0
check() {
   local label="$1" got="$2" want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')"
      fail=$((fail + 1))
   fi
}

## Run uwtwrapper and report which chain ran via the globals torsocks_ran
## (yes/no) and uwtexec_ran (yes/no). Extra NAME=VALUE pairs tune the case.
torsocks_ran=no
uwtexec_ran=no
run_dispatch() {
   local t_mark u_mark env_args
   t_mark="$(mktemp --tmpdir="${test_dir}")"
   u_mark="$(mktemp --tmpdir="${test_dir}")"
   env_args=(
      PATH="${base_path}"
      HOME="${test_dir}"
      uwtwrapper_parent="${app_base}"
      uwtexec_bin="${uwtexec_stub}"
      HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_PATH}"
      TORSOCKS_MARK="${t_mark}"
      UWTEXEC_MARK="${u_mark}"
   )
   env -i "${env_args[@]}" "$@" "${uwtwrapper}"
   if [ -s "${t_mark}" ]; then torsocks_ran=yes; else torsocks_ran=no; fi
   if [ -s "${u_mark}" ]; then uwtexec_ran=yes; else uwtexec_ran=no; fi
}

## Case 1: default -> torsocks prepended, then uwtexec.
run_dispatch
check "default: torsocks prepended" "${torsocks_ran}" "yes"
check "default: uwtexec stage ran"  "${uwtexec_ran}"  "yes"

## Case 2: uwtwrapper_global=0 -> bare uwtexec, torsocks NOT used.
run_dispatch uwtwrapper_global=0
check "global-off: torsocks NOT used" "${torsocks_ran}" "no"
check "global-off: uwtexec stage ran" "${uwtexec_ran}"  "yes"

## Case 3: UWT_DEV_PASSTHROUGH=1 -> torsocks emptied, bare uwtexec.
run_dispatch UWT_DEV_PASSTHROUGH=1
check "passthrough: torsocks NOT used" "${torsocks_ran}" "no"
check "passthrough: uwtexec stage ran" "${uwtexec_ran}"  "yes"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
