#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## docker/derivative-maker-docker-run bind-mounts the host binary volume (~/binary_mnt) into the
## container as ~/derivative-binary, shared across concurrent builds. It must forward dist_build_slot
## into the container so a laned build writes to the per-lane subdir (~/binary_mnt/<slot>) and two
## builds in different lanes do not collide on that one shared mount. The REAL conditional block is
## extracted and eval'd (no copy to drift): set -> append `--env dist_build_slot=<slot>`; unset or
## empty -> append nothing. Canary: fails on the pre-lane docker-run (no passthrough).

## File-wide: dist_build_slot is read by the `eval`'d block extracted from docker-run (not
## statically visible to shellcheck).
# shellcheck disable=SC2034
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

dm_checkout="${DERIVATIVE_MAKER_DIR:-${HOME}/derivative-maker}"
docker_run="${dm_checkout}/docker/derivative-maker-docker-run"
if [ ! -r "${docker_run}" ]; then
   printf '%s\n' "FAIL: cannot read ${docker_run}" >&2
   exit 1
fi

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $*"; }

## Extract the real passthrough block: the column-0 'if' testing dist_build_slot through its
## closing 'fi'. Keyed on the variable, not the guard's spelling.
block="$(sed -n '/^if .*dist_build_slot/,/^fi/p' -- "${docker_run}")"
if [ -z "${block}" ]; then
   fail "docker-run has no dist_build_slot passthrough block (not forwarding the lane)"
   printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip"
   exit 1
fi

## in_opts <needle> <opts...>: is <needle> one of the array elements?
in_opts() {
   local n="$1"; shift
   local e
   for e in "$@"; do
      if [ "${e}" = "${n}" ]; then
         return 0
      fi
   done
   return 1
}

## set -> appended.
docker_run_opts=()
dist_build_slot="sess-XYZ"
eval "${block}"
if in_opts "dist_build_slot=sess-XYZ" "${docker_run_opts[@]}" && in_opts "--env" "${docker_run_opts[@]}"; then
   pass "dist_build_slot set -> --env dist_build_slot=<slot> appended"
else
   fail "dist_build_slot set but the --env passthrough was not appended"
fi

## empty -> nothing appended (the -n guard).
docker_run_opts=()
dist_build_slot=""
eval "${block}"
if [ "${#docker_run_opts[@]}" -eq 0 ]; then
   pass "empty dist_build_slot -> nothing appended"
else
   fail "empty dist_build_slot still appended options: ${docker_run_opts[*]}"
fi

## unset -> nothing appended (nounset-safe guard).
docker_run_opts=()
unset dist_build_slot
eval "${block}"
if [ "${#docker_run_opts[@]}" -eq 0 ]; then
   pass "unset dist_build_slot -> nothing appended"
else
   fail "unset dist_build_slot still appended options: ${docker_run_opts[*]}"
fi

printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
