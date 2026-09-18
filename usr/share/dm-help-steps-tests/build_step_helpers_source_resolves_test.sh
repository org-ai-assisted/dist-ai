#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Every build step that uses build-step-helpers.bsh must source it by a
## CWD-independent path. The step sources it AFTER `source variables`, which
## leaves the working directory outside help-steps; a bare `source
## build-step-helpers.bsh` then resolves via neither PATH nor CWD and the build
## aborts (observed: both iso + qcow2 CI legs failed at 1200 with
## "build-step-helpers.bsh: No such file or directory"). `source pre`/`variables`
## stay bare only because they run while the CWD is still help-steps.
##
## Behavioral: the step's real source line is evaluated from a foreign CWD with
## the step's real MYDIR; the lib must load (a known function becomes defined).
## The canary proves a bare-name source would NOT resolve from that CWD, so the
## check has teeth.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

lib="${dm_checkout}/help-steps/build-step-helpers.bsh"
if [ ! -r "${lib}" ]; then
   printf '%s\n' "FAIL: cannot read ${lib}" >&2
   exit 1
fi

## a directory that is NOT help-steps, to prove the source resolves independent
## of the working directory
foreign_cwd="$( mktemp -d )"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${foreign_cwd}"; }
trap cleanup EXIT

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

## a function the lib defines; its presence proves the source actually loaded
probe_fn="require-ext-type"

## build steps that source the helper library
steps=(
   1200_prepare-build-machine
   3500_install-packages
   4350_reimage-raw-reproducible
)

for step in "${steps[@]}"; do
   step_file="${dm_checkout}/build-steps.d/${step}"
   if [ ! -r "${step_file}" ]; then
      fail "cannot read build step ${step_file}"
      continue
   fi

   ## the exact line the step uses to source the helper library
   src_line="$( grep -E '^[[:space:]]*source[[:space:]].*build-step-helpers\.bsh' -- "${step_file}" | head -1 )"
   if [ -z "${src_line}" ]; then
      fail "${step}: sources no build-step-helpers.bsh"
      continue
   fi

   ## Evaluate ONLY that line, from a CWD that is NOT help-steps, with MYDIR set
   ## as the real step sets it (dirname of the step = build-steps.d). The lib
   ## must load regardless of CWD.
   if (
         cd "${foreign_cwd}" || exit 9
         # shellcheck disable=SC2034
         MYDIR="${dm_checkout}/build-steps.d"
         eval "${src_line}" 2>/dev/null || exit 1
         declare -F "${probe_fn}" >/dev/null 2>&1 || exit 2
      ); then
      pass "${step}: sources the helper library CWD-independently"
   else
      fail "${step}: helper source does not resolve from a foreign CWD (bare name?): ${src_line}"
   fi
done

## --- CANARY: a bare-name source would NOT resolve from a foreign CWD ---------
## This is the exact regression the test guards; if it resolved, the behavioral
## check above would be meaningless.
bare_resolves=no
(
   cd "${foreign_cwd}" || exit 9
   source build-step-helpers.bsh 2>/dev/null
) && bare_resolves=yes
if [ "${bare_resolves}" = "no" ]; then
   pass 'canary: a bare-name source fails from a foreign CWD (the guarded regression)'
else
   fail 'canary broken: a bare-name source resolved from a foreign CWD'
fi

summary_line="===== build-step helper source: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
