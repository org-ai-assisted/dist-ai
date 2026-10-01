#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression (functional): wl-headless-run must PASS THE CALLER'S STDIN through to the
## command it runs. The command is launched as `setsid "$@" <&0 &`; without the `<&0` a `&`
## async command inherits /dev/null for stdin (job control is off in a script) and setsid
## also drops the controlling terminal, so any stdin-reading command would get immediate EOF.
## All current suites run --no-autoconfirm and read no stdin, so none break today -- this
## locks the general wrapper so a future stdin-reading caller keeps its input.
##
## Drives the REAL wl-headless-run with start/stop STUBBED (WL_HEADLESS_LIB), so the setsid
## invocation runs with no live compositor. A sentinel line is PIPED into the runner (run in
## the FOREGROUND, so the runner's own fd 0 is the pipe); a reader command reads one line and
## records it. Pre-fix (no `<&0`) the read hits EOF and the record is empty.
##
## Subject: usr/share/dist-ai-tests-common/wl-headless-run (setsid "$@" <&0 & stdin passthrough).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

run=''
for cand in \
   "${WL_HEADLESS_RUN:-}" \
   "${script_dir}/../dist-ai-tests-common/wl-headless-run" \
   '/usr/share/dist-ai-tests-common/wl-headless-run'; do
   if [ -n "${cand}" ] && [ -x "${cand}" ]; then
      run="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${run}" ]; then
   printf '%s\n' 'FATAL: wl-headless-run not found (set WL_HEADLESS_RUN)' >&2
   exit 1
fi

pass=0
fail=0
check() {  ## $1=label $2=ok?(non-empty=pass)
   if [ -n "$2" ]; then
      printf '%s\n' "PASS: $1"; pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $1"; fail=$(( fail + 1 ))
   fi
}

work="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${work}" 2>/dev/null || true
}
trap cleanup EXIT

## Stub lib: start/stop are no-ops, so wl-headless-run reaches its setsid+wait path with no
## real labwc. wl_headless_selfheal_reexec is intentionally left undefined -> self-heal skips.
stub_lib="${work}/wl-headless-lib.bash"
{
   printf '%s\n' '# stub for wl_headless_stdin_passthrough_test'
   printf '%s\n' 'wl_headless_start() { : ; }'
   printf '%s\n' 'wl_headless_stop() { : ; }'
} > "${stub_lib}"

## Reader command (a real script, not an inline `-c`): read ONE line of stdin, record it to the
## path in $1. It receives the caller's stdin only if wl-headless-run propagated fd 0 via `<&0`.
reader="${work}/reader.bash"
cat > "${reader}" <<'READER'
#!/bin/bash
got=""
IFS= read -r got
printf '%s' "${got}" > "$1"
READER
chmod +x -- "${reader}"

sentinel='wl-headless-stdin-canary-7f3a9c'
out="${work}/got"

## Foreground run (do NOT background: a `&` here would point the runner's own fd 0 at /dev/null
## and defeat the test). timeout bounds a wedge; the reader gets the piped line only via `<&0`.
rc=0
printf '%s\n' "${sentinel}" \
   | timeout --kill-after=10 30 env WL_HEADLESS_LIB="${stub_lib}" "${run}" --no-autoconfirm -- \
       "${reader}" "${out}" \
   || rc="$?"

got="$(cat -- "${out}" 2>/dev/null || true)"

check "wl-headless-run exits cleanly (rc=${rc})" "$( [ "${rc}" -eq 0 ] && printf '1' )"
check "command receives the caller's piped stdin (got='${got}')" \
   "$( [ "${got}" = "${sentinel}" ] && printf '1' )"

printf '%s\n' ''
printf '%s\n' "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
