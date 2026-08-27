#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Argument handling for the CI helpers that other tools depend on.
##
## WHY: dm-ci-job-watch answered '--help' with
## "line 27: $2: unbound variable" -- a crash where the usage text belongs. A
## tool whose help is a crash teaches you not to trust its other output, and this
## one is what a stall supervisor reads a build verdict from.
##
## dist-ai-dev-symlinks puts this checkout on PATH. It must never clobber a real
## file or shadow a system command, because the failure mode is silent: the wrong
## binary runs and everything downstream reports confidently about the wrong code.
##
## Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DIST_AI_DIR:-}" ]; then
   dist_ai_dir="${DIST_AI_DIR}"
else
   dist_ai_dir="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/../../.." && pwd )"
fi
bin_dir="${dist_ai_dir}/usr/bin"

for required in dm-ci-job-watch dist-ai-dev-symlinks; do
   if [ ! -x "${bin_dir}/${required}" ]; then
      printf '%s\n' "FAIL: ${required} not executable at ${bin_dir}" >&2
      exit 1
   fi
done

pass_count=0
fail_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
fail() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: $*" >&2
}

work_dir="$( mktemp --directory )"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${work_dir}"
}
trap cleanup EXIT

## --- dm-ci-job-watch --help must be usage text, not a crash -----------------
status=0
output="$( "${bin_dir}/dm-ci-job-watch" --help 2>&1 )" || status="$?"
if [ "${status}" -eq 0 ] && [[ "${output}" == *"usage: dm-ci-job-watch"* ]]; then
   pass 'dm-ci-job-watch --help prints usage and exits 0'
else
   fail "--help gave status=${status} output=${output}"
fi

## The specific old symptom, asserted directly: no unbound-variable diagnostic.
if [[ "${output}" != *"unbound variable"* ]]; then
   pass 'dm-ci-job-watch --help does not crash on an unbound argument'
else
   fail "--help still crashes: ${output}"
fi

## Too few arguments is a usage error (2), distinct from a runtime failure.
status=0
"${bin_dir}/dm-ci-job-watch" "${work_dir}/p" >/dev/null 2>&1 || status="$?"
if [ "${status}" -eq 2 ]; then
   pass 'dm-ci-job-watch exits 2 on too few arguments'
else
   fail "expected exit 2 for one argument, got ${status}"
fi

## --- dist-ai-dev-symlinks must not clobber or shadow ------------------------
## A throwaway HOME, so the real ~/.local/bin is never touched by this test.
fake_home="${work_dir}/home"
mkdir --parents -- "${fake_home}/.local/bin"

status=0
output="$( HOME="${fake_home}" PATH="${fake_home}/.local/bin:/usr/bin:/bin" "${bin_dir}/dist-ai-dev-symlinks" --dry-run 2>&1 )" || status="$?"
if [ "${status}" -eq 0 ] && [[ "${output}" == *"would link"* ]]; then
   pass 'dist-ai-dev-symlinks --dry-run reports what it would link'
else
   fail "--dry-run gave status=${status} output=${output}"
fi

## --dry-run must not have created anything.
if [ -z "$( ls --almost-all -- "${fake_home}/.local/bin" )" ]; then
   pass '--dry-run creates no links'
else
   fail '--dry-run created links'
fi

## A REAL file at a target name must survive. Overwriting it would destroy a
## file the user put there.
real_file="${fake_home}/.local/bin/dm-preflight"
printf '%s\n' 'do not clobber me' > "${real_file}"
status=0
output="$( HOME="${fake_home}" PATH="${fake_home}/.local/bin:/usr/bin:/bin" "${bin_dir}/dist-ai-dev-symlinks" 2>&1 )" || status="$?"
if [ -f "${real_file}" ] && [ ! -L "${real_file}" ] \
   && grep --quiet --fixed-strings 'do not clobber me' -- "${real_file}"; then
   pass 'a real file at a target name is left untouched'
else
   fail 'a real file was clobbered by the symlink pass'
fi

## ...and it must SAY so rather than skipping silently.
if [[ "${output}" == *"skip:"*"dm-preflight"* ]]; then
   pass 'the skipped file is reported, not silently passed over'
else
   fail "the skip was not reported: ${output}"
fi

## The other tools still got linked, and they point at THIS checkout.
linked_probe="${fake_home}/.local/bin/dm-build-step-fn"
if [ -L "${linked_probe}" ] \
   && [ "$( readlink --canonicalize -- "${linked_probe}" )" = "${bin_dir}/dm-build-step-fn" ]; then
   pass 'tools are linked to this checkout, so an edit is live'
else
   fail 'dm-build-step-fn was not linked to this checkout'
fi

## Re-running is a no-op, not a pile of churn: it must report them as current.
status=0
output="$( HOME="${fake_home}" PATH="${fake_home}/.local/bin:/usr/bin:/bin" "${bin_dir}/dist-ai-dev-symlinks" 2>&1 )" || status="$?"
if [ "${status}" -eq 0 ] && [[ "${output}" == *"already current"* ]] \
   && [[ "${output}" != *" 0 already current"* ]]; then
   pass 're-running is idempotent and reports links as already current'
else
   fail "re-run gave status=${status} output=${output}"
fi

## --- CANARY: the harness can fail at all ------------------------------------
status=0
"${bin_dir}/dm-ci-job-watch" >/dev/null 2>&1 || status="$?"
if [ "${status}" -ne 0 ]; then
   pass 'canary: dm-ci-job-watch with no arguments exits non-zero'
else
   fail 'canary broken: dm-ci-job-watch exits 0 with no arguments'
fi

summary_line="===== ci tooling: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
