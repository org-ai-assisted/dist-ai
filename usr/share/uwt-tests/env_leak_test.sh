#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## uwt environment hygiene: the wrapped application must NOT inherit uwt's
## internal bookkeeping, and must run under the CALLER's locale (not uwt's
## internal LC_ALL=C).
##
## uwt passes uwtwrapper_parent / uwtwrapper_zeroarg / uwtwrapper_counter (and
## the rest of the uwtwrapper_* / timeprivacy_* family, plus UWT_DEV_PASSTHROUGH)
## between its stages by EXPORTING them, and forces LC_ALL=C for its own parsing.
## Left uncleaned, all of that reaches the wrapped application. Two cleanup
## points fix it:
##   - uwtexec, the chokepoint every normal exec path routes through (torsocks,
##     global-off, per-app-off, bindp, faketime);
##   - uwtwrapper's two symlink-passthrough execs, which bypass uwtexec.
## Both strip the bookkeeping and restore the caller's LC_ALL (saved by
## uwtwrapper before it forced C; unset when the caller had none).
##
## Method: drive the REAL uwtwrapper / uwtexec against a stub application that
## records its own exported-variable NAMES and its LC_ALL, under a hermetic
## `env -i` so the recorded set is exactly what uwt delivered. A transparent
## torsocks stub on PATH keeps the default path running without real Tor.
## torsocks' LD_PRELOAD and bindp's BIND_ADDR are intentionally NOT asserted
## against: the wrapped app genuinely needs those; they are not uwt bookkeeping.
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
uwtexec="${libexec_dir}/uwtexec"

## strings.bsh / has.bsh: the wrapper sources them via ${HELPER_SCRIPTS_PATH:-}
## (set by dist-ai-tests-all's wire; unset -> installed /usr/libexec).
[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""
strings_bsh="${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/strings.bsh"

if [ ! -r "${uwtwrapper}" ] || [ ! -r "${uwtexec}" ]; then
   printf '%s\n' "FATAL: uwtwrapper/uwtexec not readable under '${libexec_dir}'" >&2
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

## Transparent torsocks stub: exec its args, add nothing to the environment, so
## the default (torsocks) path runs with no real Tor and no stub-introduced var.
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'exec "$@"'
} > "${bin_dir}/torsocks"
chmod 0755 -- "${bin_dir}/torsocks"

## Write a stub wrapped-application that records, to the two paths it is given,
## its own exported-variable NAMES (sorted; $1) and its LC_ALL ($2, the literal
## __UNSET__ when LC_ALL is unset, distinct from empty). compgen is a bash
## builtin, so no coreutils are needed on the hermetic PATH.
write_recorder() {
   ## Literal shell written to a file; its $-expressions expand when the
   ## recorder runs, not here.
   # shellcheck disable=SC2016
   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' 'compgen -e | LC_ALL=C sort > "$1"'
      printf '%s\n' 'printf "%s\n" "${LC_ALL-__UNSET__}" > "$2"'
   } > "$1"
   chmod 0755 -- "$1"
}

## uwt-internal variables that must never reach the wrapped application.
internal_vars=(
   uwtwrapper_parent
   uwtwrapper_zeroarg
   uwtwrapper_counter
   uwtwrapper_verbose
   uwtwrapper_max
   uwtwrapper_global
   timeprivacy_global
   UWT_DEV_PASSTHROUGH
)

base_path="${bin_dir}:/usr/bin:/bin"

pass=0
fail=0
## $1 label, $2 names-file, $3 lcall-file, $4 expected LC_ALL (__UNSET__ or a
## value). Fails if any internal var leaked or LC_ALL is not the caller's.
check_case() {
   local label="$1" names="$2" lcall="$3" want_lcall="$4" var leaked="" got_lcall
   for var in "${internal_vars[@]}"; do
      if grep --quiet -x -- "${var}" "${names}"; then
         leaked+=" ${var}"
      fi
   done
   got_lcall="$(cat -- "${lcall}")"
   if [ -n "${leaked}" ]; then
      printf '%s\n' "FAIL: ${label}: leaked:${leaked}"
      fail=$((fail + 1))
   elif [ "${got_lcall}" != "${want_lcall}" ]; then
      printf '%s\n' "FAIL: ${label}: LC_ALL='${got_lcall}', want '${want_lcall}'"
      fail=$((fail + 1))
   else
      printf '%s\n' "PASS: ${label}: no leak, LC_ALL='${got_lcall}'"
      pass=$((pass + 1))
   fi
}

## In checkout mode, uwtexec_bin + HELPER_SCRIPTS_PATH are injected to reach the
## checkout; the fix strips uwtexec_bin, and HELPER_SCRIPTS_PATH is unset in
## production, so neither is in internal_vars.
uwt_env_common=( PATH="${base_path}" HOME="${test_dir}" )
if [ -n "${UWT_REPO}" ]; then
   uwt_env_common+=( uwtexec_bin="${uwtexec}" HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_PATH}" )
fi

## --- Main paths (through uwtexec): parent has a regular .anondist-orig. ---
app_base="${test_dir}/myapp"
write_recorder "${app_base}.anondist-orig"
n="${test_dir}/n_main"
l="${test_dir}/l_main"

run_main() {
   ## $1 names-out $2 lcall-out; remaining args are extra NAME=VALUE env pairs.
   local names="$1" lc="$2"; shift 2
   env -i "${uwt_env_common[@]}" uwtwrapper_parent="${app_base}" "$@" \
      "${uwtwrapper}" "${names}" "${lc}"
}

## Case 1: default (torsocks) path, caller has no LC_ALL -> app LC_ALL unset.
run_main "${n}1" "${l}1"
check_case "default torsocks path" "${n}1" "${l}1" "__UNSET__"

## Case 2: global-off path (uwtwrapper_global=0 -> bare uwtexec, no torsocks).
run_main "${n}2" "${l}2" uwtwrapper_global=0
check_case "global-off path" "${n}2" "${l}2" "__UNSET__"

## Case 3: dev-passthrough path (UWT_DEV_PASSTHROUGH=1 -> torsocks skipped).
run_main "${n}3" "${l}3" UWT_DEV_PASSTHROUGH=1
check_case "dev-passthrough path" "${n}3" "${l}3" "__UNSET__"

## Case 4: the caller's LC_ALL reaches the app unchanged; uwt must not force C.
## Uses C.UTF-8 (always available, so no setlocale noise) yet distinct from C.
run_main "${n}4" "${l}4" LC_ALL=C.UTF-8
check_case "caller LC_ALL preserved" "${n}4" "${l}4" "C.UTF-8"

## --- Symlink-passthrough paths (bypass uwtexec, cleaned in uwtwrapper). ---
recorder="${test_dir}/recorder"
write_recorder "${recorder}"

## Case 5: uwtwrapper_parent itself is a symlink with no .anondist wrapper ->
## uwtwrapper execs the symlink target directly.
sp="${test_dir}/symparent"
ln -s -- "${recorder}" "${sp}"
env -i "${uwt_env_common[@]}" uwtwrapper_parent="${sp}" \
   "${uwtwrapper}" "${test_dir}/n5" "${test_dir}/l5"
check_case "symlink parent passthrough" "${test_dir}/n5" "${test_dir}/l5" "__UNSET__"

## Case 6: parent.anondist-orig is a symlink (e.g. gpg2.anondist-orig -> gpg) ->
## uwtwrapper execs the symlink target directly.
so="${test_dir}/symorig"
ln -s -- "${recorder}" "${so}.anondist-orig"
env -i "${uwt_env_common[@]}" uwtwrapper_parent="${so}" \
   "${uwtwrapper}" "${test_dir}/n6" "${test_dir}/l6"
check_case "symlink anondist-orig passthrough" "${test_dir}/n6" "${test_dir}/l6" "__UNSET__"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
