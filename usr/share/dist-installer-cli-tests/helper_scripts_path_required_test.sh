#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for usability-misc' build-dist-installer-cli.
##
## Bug: the generator resolved the helper-scripts to inline as
## "${HELPER_SCRIPTS_PATH:-}/usr/libexec/helper-scripts/". Unset, that defaults
## to the INSTALLED /usr/libexec/helper-scripts, which drifts from the pinned
## checkout -- a stale installed lockfile.sh once produced a standalone that
## broke on any argument. Every supported caller (help-steps/pre, parse-cmd,
## variables; dist-ai-tests-all in CI) exports HELPER_SCRIPTS_PATH, so the fix
## is to REFUSE when unset instead of silently inlining the installed copy.
##
## SUBJECT: the REAL build-dist-installer-cli, executed with HELPER_SCRIPTS_PATH
## unset. It must exit non-zero with the actionable error BEFORE it regenerates
## the standalone (no "BUILD: SUCCESS"). Driving the real generator in place is
## safe: the refusal fires before the cp/process/mv write step, so the committed
## standalone is never touched.
##
## Canary: on the old code an unset run defaults to /usr/libexec/helper-scripts
## and (when present) regenerates to completion, printing "BUILD: SUCCESS" and
## exiting 0 -- so the exit-non-zero + actionable-error assertions fail.
##
## Self-contained; no root, no network. A missing subject is FATAL, never a skip.

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
generator="${repo}/usr/share/usability-misc/build-dist-installer-cli"
if [ ! -r "${generator}" ]; then
   printf '%s\n' "FATAL: not readable: '${generator}'" >&2
   printf '%s\n' "set USABILITY_MISC_REPO to a usability-misc checkout." >&2
   exit 1
fi

pass_count=0
fail_count=0
ok() {
   printf '%s\n' "PASS: ${1}"
   pass_count=$(( pass_count + 1 ))
}
notok() {
   printf '%s\n' "FAIL: ${1}" >&2
   if [ -n "${2:-}" ]; then
      printf '%s\n' "      ${2}" >&2
   fi
   fail_count=$(( fail_count + 1 ))
}

## Run the real generator with HELPER_SCRIPTS_PATH cleared from the environment.
rc=0
out="$( env --unset=HELPER_SCRIPTS_PATH bash "${generator}" 2>&1 )" || rc="$?"

## 1. It refuses (non-zero) when HELPER_SCRIPTS_PATH is unset.
if [ "${rc}" -ne 0 ]; then
   ok "refuses with a non-zero exit when HELPER_SCRIPTS_PATH is unset"
else
   notok "accepted an unset HELPER_SCRIPTS_PATH (rc=0)" \
      "$(printf '%s' "${out}" | tail -n3 | tr '\n' '|')"
fi

## 2. The error names HELPER_SCRIPTS_PATH (actionable), not the old silent
## fallback to /usr/libexec.
if grep --quiet --fixed-strings -- 'HELPER_SCRIPTS_PATH is unset' <<< "${out}"; then
   ok "emits the actionable HELPER_SCRIPTS_PATH error"
else
   notok "missing the actionable HELPER_SCRIPTS_PATH error" \
      "$(printf '%s' "${out}" | tail -n3 | tr '\n' '|')"
fi

## 3. It refused BEFORE the generation step: no standalone was (re)built, so the
## committed file is never clobbered by a stale installed helper-scripts.
if grep --quiet --fixed-strings -- 'BUILD: SUCCESS' <<< "${out}"; then
   notok "regenerated the standalone despite the unset HELPER_SCRIPTS_PATH"
else
   ok "did not reach the generation step (standalone untouched)"
fi

printf '%s\n' ""
printf '%s\n' "===== build-dist-installer-cli HELPER_SCRIPTS_PATH-required: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
