#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## uwtexec argv/required-env contract: uwtexec is the exec chokepoint that
## re-execs the wrapped program with argv[0] preserved. This drives the REAL
## uwtexec, black-box, under a hermetic `env -i`, and asserts:
##   - the two required-env guards (uwtwrapper_zeroarg / uwtwrapper_parent),
##     each exit 1 with its own message;
##   - `exec -a` sets argv[0] to uwtwrapper_zeroarg (NOT the real path) and
##     forwards the trailing arguments verbatim to ${uwtwrapper_parent}.anondist-orig.
##
## uwtexec's env-strip + LC_ALL-restore behavior is covered by env_leak_test.sh
## and is NOT re-tested here.
##
## uwtexec sources nothing, so no HELPER_SCRIPTS_PATH is needed. Targets the
## installed package by default; set UWT_REPO to test a checkout. A missing
## subject is a REQUIRED-dependency environment bug -> exit 1 (FATAL), never a
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
uwtexec="${libexec_dir}/uwtexec"

if [ ! -x "${uwtexec}" ]; then
   printf '%s\n' "FATAL: uwtexec not executable at '${uwtexec}'" >&2
   printf '%s\n' "set UWT_REPO to a uwt checkout, or install uwt" >&2
   exit 1
fi

test_dir="$(mktemp --directory)"
cleanup_handler() {
   ## '|| true': a cleanup failure must not clobber the script's real exit code.
   safe-rm -r -f -- "${test_dir}" || true
}
trap cleanup_handler EXIT

pass=0
fail=0
## $1 label, $2 ok (non-empty = pass), $3 detail printed on failure.
assert() {
   local label="$1" ok="$2" detail="$3"
   if [ -n "${ok}" ]; then
      printf '%s\n' "PASS: ${label}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label}: ${detail}"
      fail=$((fail + 1))
   fi
}

base_path='/usr/bin:/bin'

## --- Case 1: uwtwrapper_zeroarg missing (unset) -> exit 1 + message. ---
rc=0
out="$(env -i PATH="${base_path}" "${uwtexec}" 2>&1)" || rc=$?
ok=""
[ "${rc}" -eq 1 ] && [[ "${out}" == *'uwtwrapper_zeroarg is required'* ]] && ok=1
assert "missing uwtwrapper_zeroarg exits 1 with message" "${ok}" "rc=${rc} out='${out}'"

## --- Case 2: uwtwrapper_zeroarg set, uwtwrapper_parent missing -> exit 1 + message. ---
rc=0
out="$(env -i PATH="${base_path}" uwtwrapper_zeroarg='someprog' "${uwtexec}" 2>&1)" || rc=$?
ok=""
[ "${rc}" -eq 1 ] && [[ "${out}" == *'uwtwrapper_parent is required'* ]] && ok=1
assert "missing uwtwrapper_parent exits 1 with message" "${ok}" "rc=${rc} out='${out}'"

## --- Case 3: argv[0] preservation + arg forwarding. ---
## uwtexec does `exec -a "${zeroarg}" "${parent}.anondist-orig" "$@"`. To observe
## the argv[0] it set, the sink MUST be a real ELF: the kernel discards argv[0]
## when it rewrites a `#!` script into an interpreter invocation, so a shebang
## stub's $0 is only its own script path -- it could never see exec -a's value.
## So the throwaway sink is /bin/bash itself (an ELF), driven via BASH_ENV: bash
## sources that file before anything else, and there reads its OWN argv from
## /proc/self/cmdline -- argv[0] = the exec -a value, the rest = the forwarded
## args. uwtexec strips only the uwt-internal vars, so BASH_ENV/REC_* reach it.
## The recorder stays inert during uwtexec's own startup (uwtexec is also a bash
## script, so it too sources BASH_ENV): uwtwrapper_zeroarg is still set there and
## uwtexec strips it before the exec, so an unset uwtwrapper_zeroarg uniquely
## marks the exec'd sink.
parent="${test_dir}/myapp"
rec_zero="${test_dir}/rec_zero"
rec_args="${test_dir}/rec_args"
recorder="${test_dir}/recorder.bash"
## The recorder is shell SOURCE text written to a file; its $-expressions are
## intentionally literal (expanded when bash runs the file, not here).
# shellcheck disable=SC2016
{
   printf '%s\n' 'if [ -n "${uwtwrapper_zeroarg:-}" ]; then'
   printf '%s\n' '   return 0'
   printf '%s\n' 'fi'
   printf '%s\n' 'mapfile -d "" -t uwt_argv < /proc/self/cmdline'
   printf '%s\n' 'printf "%s\n" "${uwt_argv[0]}" > "${REC_ZERO}"'
   ## NUL-delimit each forwarded arg so the argv BOUNDARIES are recorded: a
   ## space-join ("${uwt_argv[*]:1}") cannot tell one arg "alpha beta" from two
   ## args "alpha" "beta", which is the whole contract under test.
   printf '%s\n' 'printf "%s\0" "${uwt_argv[@]:1}" > "${REC_ARGS}"'
   printf '%s\n' 'exit 0'
} > "${recorder}"
ln -s -- /bin/bash "${parent}.anondist-orig"

rc=0
env -i PATH="${base_path}" BASH_ENV="${recorder}" \
   REC_ZERO="${rec_zero}" REC_ARGS="${rec_args}" \
   uwtwrapper_zeroarg='/some/custom/argv0' uwtwrapper_parent="${parent}" \
   "${uwtexec}" alpha beta || rc=$?

got_zero=""
[ -r "${rec_zero}" ] && got_zero="$(cat -- "${rec_zero}")"

ok=""
[ "${rc}" -eq 0 ] && [ "${got_zero}" = '/some/custom/argv0' ] && ok=1
assert "exec -a sets argv[0] to uwtwrapper_zeroarg" "${ok}" \
   "rc=${rc} argv[0]='${got_zero}' want '/some/custom/argv0'"

## Compare the recorded argv BYTE-FOR-BYTE against the NUL-delimited expectation:
## 'alpha beta' as one arg vs 'alpha','beta' as two differ here (they would not
## under a space-join). cmp handles the embedded NULs a shell var cannot hold.
expected_args="${test_dir}/expected_args"
printf '%s\0' alpha beta > "${expected_args}"
ok=""
[ -r "${rec_args}" ] && cmp --quiet -- "${rec_args}" "${expected_args}" && ok=1
## NUL is unprintable; render it as '|' for the failure detail only.
got_args_show=""
[ -r "${rec_args}" ] && got_args_show="$(tr '\0' '|' < "${rec_args}")"
assert "trailing args forwarded verbatim (argv boundaries)" "${ok}" \
   "args='${got_args_show}' want 'alpha|beta|'"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
