#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Root cause this gate exists for: `source variables` intentionally cd's into
## source_code_folder_dist (variables.d/10_core.bsh, "by design" -- every build
## step runs from the source root afterwards). So a script that sources a
## help-steps sibling by BARE NAME *after* `source variables` resolves via
## neither PATH nor CWD and the build aborts (observed: iso + qcow2 CI legs died
## at 1200 with "build-step-helpers.bsh: No such file or directory"). The correct
## idiom is a path anchored to the script's OWN location -- ${MYDIR}/.. or
## $(dirname ${BASH_SOURCE[0]}) -- exactly as help-steps/pre sources retry-run.
##
## This gate DISCOVERS every consumer of build-step-helpers.bsh (so a new one, or
## dm-raw-to-iso, is covered without editing this test) and asserts each sources
## it by a self-anchored path, never a bare/CWD-relative name. A behavioral proof
## + canary back the structural check: a self-anchored path loads from any CWD, a
## bare name does not.

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

## the line by which a script sources the helper library
src_line_of() {
   grep -E '^[[:space:]]*source[[:space:]].*build-step-helpers\.bsh' -- "$1" | head -1
}

## --- discover every consumer and require a self-anchored source ---------------
## Any file under build-steps.d/ or help-steps/ that sources the library (the
## library itself excluded). Discovery, not a hardcoded list, so a new consumer
## cannot silently escape the check.
mapfile -t consumers < <(
   grep -rlE 'source[[:space:]].*build-step-helpers\.bsh' \
      -- "${dm_checkout}/build-steps.d" "${dm_checkout}/help-steps" 2>/dev/null \
   | grep -v '/build-step-helpers\.bsh$' | sort)

if [ "${#consumers[@]}" -eq 0 ]; then
   fail 'discovery found no consumer of build-step-helpers.bsh (grep broken?)'
fi

for consumer in "${consumers[@]}"; do
   src_line="$( src_line_of "${consumer}" )"
   ## The source ARGUMENT must anchor to the script's own location so it resolves
   ## regardless of CWD. ${MYDIR} (=dirname of the script) and ${BASH_SOURCE[0]}
   ## are the two anchors in this tree; a bare or CWD-relative name has neither.
   case "${src_line}" in
      *'${MYDIR}'*|*'BASH_SOURCE'*)
         pass "${consumer##*/}: sources the helper by a self-anchored path"
         ;;
      *)
         fail "${consumer##*/}: helper source is not self-anchored (bare/CWD-relative): ${src_line}"
         ;;
   esac
done

## --- behavioral proof: a self-anchored path loads from a foreign CWD ----------
foreign_cwd="$( mktemp -d )"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${foreign_cwd}"; }
trap cleanup EXIT

## a function the lib defines; its presence proves the source actually loaded
probe_fn="require-ext-type"
if (
      cd "${foreign_cwd}" || exit 9
      # shellcheck disable=SC2034
      MYDIR="${dm_checkout}/build-steps.d"
      source "${MYDIR}/../help-steps/build-step-helpers.bsh" 2>/dev/null || exit 1
      declare -F "${probe_fn}" >/dev/null 2>&1 || exit 2
   ); then
   pass 'behavioral: a ${MYDIR}-anchored source loads the lib from a foreign CWD'
else
   fail 'behavioral: a ${MYDIR}-anchored source failed to load from a foreign CWD'
fi

## --- CANARY: a bare-name source would NOT resolve from a foreign CWD ----------
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
