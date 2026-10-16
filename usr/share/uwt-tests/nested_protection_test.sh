#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## uwt nested-execution (infinite-recursion) protection.
##
## uwtwrapper increments and EXPORTS uwtwrapper_counter (nested_protection), and
## uwtexec / uwtwrapper's symlink-passthrough deliberately KEEP it when stripping
## the rest of uwt's per-invocation plumbing. The recursion path runs THROUGH the
## exec'd application (the real app, or a symlink target, re-invokes a wrapped
## command), so the counter must survive each exec to accumulate depth and trip
## uwtwrapper_max. If the counter were stripped, depth would reset to 0 at every
## level and a genuine wrapper loop would never terminate.
##
## Asserted:
##   - counter PROPAGATES through the exec with the incremented value (caller
##     N -> app N+1), while uwtwrapper_parent / uwtwrapper_zeroarg are stripped;
##   - a clean start yields counter 1; a garbage counter resets to 0 then 1;
##   - the guard fires (exit 255) at the default max (10) and at an explicit max;
##   - a REAL recursive wrapper chain terminates via the guard rather than
##     looping forever -- bounded by `timeout`, so a BROKEN build (counter
##     stripped) FAILS fast here instead of hanging the suite.
##
## Method: drive the REAL uwtwrapper / uwtexec under a hermetic `env -i` with a
## transparent torsocks stub on PATH. A stub application records its own
## uwtwrapper_counter and its exported-variable NAMES. The recursion case uses a
## .anondist entry that re-execs the wrapper and an .anondist-orig that re-enters
## that entry, reproducing a true wrapper loop.
##
## Targets the installed package by default; set UWT_REPO to test a checkout
## (then HELPER_SCRIPTS_PATH must point at a helper-scripts checkout so the
## wrapper can source strings.bsh / has.bsh). A missing subject or helper
## library, a missing `timeout`, or host uwt config that would break hermetic
## isolation is a REQUIRED-dependency environment bug -> exit 1 (FATAL), never a
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
if ! type -P timeout >/dev/null; then
   printf '%s\n' "FATAL: 'timeout' not on PATH (coreutils); needed to bound the recursion case" >&2
   exit 1
fi

## uwtwrapper sources /etc/uwt.d/*.conf and /usr/local/etc/uwt.d/*.conf from
## HARDCODED paths (intentionally not env-injectable, so a torification wrapper
## cannot be pointed at rogue config). Such a file could set uwtwrapper_max /
## uwtwrapper_global and break these hermetic expectations, so refuse to run with
## host config present rather than report a false result.
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

bin_dir="${test_dir}/bin"
mkdir -p -- "${bin_dir}"

## Transparent torsocks stub: exec its args, add nothing to the environment, so
## the default (torsocks) path runs with no real Tor. The stub body is literal
## shell written to a file; its $-expressions expand when the stub runs.
# shellcheck disable=SC2016
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'exec "$@"'
} > "${bin_dir}/torsocks"
chmod 0755 -- "${bin_dir}/torsocks"

## Stub wrapped-application: record (to the two given paths) its exported-variable
## NAMES (sorted; $1) and its uwtwrapper_counter ($2, literal __UNSET__ when
## unset). compgen is a bash builtin, so no coreutils are needed on the PATH.
# shellcheck disable=SC2016
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'compgen -e | LC_ALL=C sort > "$1"'
   printf '%s\n' 'printf "%s\n" "${uwtwrapper_counter-__UNSET__}" > "$2"'
} > "${test_dir}/recorder"
chmod 0755 -- "${test_dir}/recorder"

base_path="${bin_dir}:/usr/bin:/bin"
uwt_env_common=( PATH="${base_path}" HOME="${test_dir}" )
if [ -n "${UWT_REPO}" ]; then
   uwt_env_common+=( uwtexec_bin="${uwtexec}" HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_PATH}" )
fi

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

## --- Propagation: the counter must survive the exec (so a nested wrapper
##     accumulates depth), while the per-invocation plumbing is stripped. ---
app_base="${test_dir}/myapp"
## The recorder doubles as the wrapped application target.
cp -- "${test_dir}/recorder" "${app_base}.anondist-orig"
chmod 0755 -- "${app_base}.anondist-orig"

names=""
counter=""
run_record() {
   ## $1 names-out $2 counter-out; remaining args are extra NAME=VALUE env pairs.
   local names_out="$1" counter_out="$2"; shift 2
   env -i "${uwt_env_common[@]}" uwtwrapper_parent="${app_base}" "$@" \
      "${uwtwrapper}" "${names_out}" "${counter_out}"
   names="$(LC_ALL=C sort < "${names_out}")"
   counter="$(cat -- "${counter_out}")"
}

## True if NAME is one of the newline-separated exported names in ${names}.
has_name() {
   [[ $'\n'"${names}"$'\n' == *$'\n'"${1}"$'\n'* ]]
}

## Returns 'leaked' if any stripped-plumbing var reached the app, else 'clean'.
plumbing_state() {
   local n
   for n in uwtwrapper_parent uwtwrapper_zeroarg uwtexec_bin uwt_caller_lc_all; do
      if has_name "${n}"; then
         printf '%s\n' "leaked:${n}"
         return 0
      fi
   done
   printf '%s\n' clean
}

## counter_present: 'yes' if uwtwrapper_counter reached the app, else 'no'.
counter_present() {
   if has_name uwtwrapper_counter; then
      printf '%s\n' yes
   else
      printf '%s\n' no
   fi
}

## Case 1: a caller counter is incremented and propagated (41 -> 42); the
## plumbing is stripped. Large uwtwrapper_max so the guard does not fire.
run_record "${test_dir}/n1" "${test_dir}/c1" uwtwrapper_counter=41 uwtwrapper_max=1000
check "set counter propagates incremented (41 -> 42)" "${counter}" "42"
check "set counter: uwtwrapper_counter reaches app" "$(counter_present)" "yes"
check "set counter: per-invocation plumbing stripped" "$(plumbing_state)" "clean"

## Case 2: a clean start (no caller counter) yields counter 1.
run_record "${test_dir}/n2" "${test_dir}/c2" uwtwrapper_max=1000
check "clean start -> counter 1" "${counter}" "1"

## Case 3: a non-numeric counter is reset to 0 then incremented to 1.
run_record "${test_dir}/n3" "${test_dir}/c3" uwtwrapper_counter=notanumber uwtwrapper_max=1000
check "garbage counter resets (notanumber -> 1)" "${counter}" "1"

## --- The guard fires (exit 255) before the application is ever exec'd. ---
## Sets globals trip_out (combined output) + trip_rc (exit code). Called
## DIRECTLY (not in a command substitution) so the globals reach the caller.
## Points the parent at a recorder that MUST NOT run (the guard precedes exec).
trip_out=""
trip_rc=0
run_trip() {
   trip_rc=0
   trip_out="$(env -i "${uwt_env_common[@]}" uwtwrapper_parent="${app_base}" "$@" \
      "${uwtwrapper}" "${test_dir}/should_not_write" "${test_dir}/should_not_write2" 2>&1)" || trip_rc=$?
}

## Case 4: default uwtwrapper_max is 10; counter 9 -> 10 trips.
run_trip uwtwrapper_counter=9
check "default max: counter 9 -> exit 255" "${trip_rc}" "255"
case "${trip_out}" in
   *"nested executions"*)
      trip_msg=ok
      ;;
   *)
      trip_msg=bad
      ;;
esac
check "default max: emits the nested-executions error" "${trip_msg}" "ok"
if [ -e "${test_dir}/should_not_write" ]; then
   app_ran=ran
else
   app_ran=no
fi
check "default max: application was NOT exec'd" "${app_ran}" "no"

## Case 5: an explicit uwtwrapper_max is honored (counter 2, max 3 -> 3 trips).
run_trip uwtwrapper_counter=2 uwtwrapper_max=3
check "explicit max 3: counter 2 -> exit 255" "${trip_rc}" "255"

## --- Case 6: a REAL recursive wrapper chain must terminate via the guard, not
##     loop forever. The .anondist entry re-execs the wrapper (re-establishing
##     the checkout wiring, as a real wrapper sets its own uwtwrapper_parent);
##     the .anondist-orig re-enters that entry. With a working counter the guard
##     trips (exit 255) in a few levels; with a broken build the counter resets
##     each level and the chain loops until `timeout` kills it (exit 124), which
##     this case then reports as a FAILURE rather than hanging. ---
rec_base="${test_dir}/loop"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' "export uwtwrapper_parent=${rec_base@Q}.anondist"
   if [ -n "${UWT_REPO}" ]; then
      printf '%s\n' "export uwtexec_bin=${uwtexec@Q}"
      printf '%s\n' "export HELPER_SCRIPTS_PATH=${HELPER_SCRIPTS_PATH@Q}"
   fi
   printf '%s\n' "exec ${uwtwrapper@Q} \"\$@\""
} > "${rec_base}.anondist"
chmod 0755 -- "${rec_base}.anondist"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' "exec ${rec_base@Q}.anondist \"\$@\""
} > "${rec_base}.anondist-orig"
chmod 0755 -- "${rec_base}.anondist-orig"

recurse_rc=0
timeout --kill-after=5 20 \
   env -i PATH="${base_path}" HOME="${test_dir}" uwtwrapper_max=4 \
   "${rec_base}.anondist" >/dev/null 2>&1 || recurse_rc=$?
check "real recursion terminates via guard (exit 255, not a 124 timeout)" \
   "${recurse_rc}" "255"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
