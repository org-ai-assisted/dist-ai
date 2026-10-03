#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## A source-able (`sourceable` skill) script sources check_runtime.bsh (which
## provides was_executed) at the top, then gates main() behind
## `if was_executed "${BASH_SOURCE[0]}"`. If that source FAILS, was_executed is
## undefined, the guard evaluates false, main() is skipped, and the script exits
## 0 -- a SILENT false pass. The shebang's `-e` does NOT save it: a `bash <script>`
## invocation ignores the shebang, so errexit is off and the failed source does
## not abort. The fix is an EXPLICIT fatal guard on the source
## (`if ! source ...; then printf ERROR >&2; exit 1; fi`).
##
## This drives the REAL scripts (no synthetic copy) under a deliberately broken
## HELPER_SCRIPTS_PATH via `bash <script>` (the mode the shebang -e cannot cover)
## and asserts a NON-ZERO exit. Canary: remove the explicit guard and the script
## exits 0, so the rc!=0 assertion flips RED -- 0 coverage would mean the guard
## is gone.
##
## A missing subject is an ENVIRONMENT BUG -> exit 1 (FATAL), never a skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   sbindir="${HELPER_SCRIPTS_REPO}/usr/sbin"
else
   sbindir='/usr/sbin'
fi

## The source-able sentinel-variant scripts this session owns. Each must fail
## LOUDLY (non-zero) when its check_runtime.bsh source cannot be resolved.
subjects=(
   "${sbindir}/shim-signed-mok-setup"
   "${sbindir}/rebuild-vbox-ga-modules"
)

for subject in "${subjects[@]}"; do
   if [ ! -r "${subject}" ]; then
      printf '%s\n' "FATAL: subject not readable at '${subject}'" >&2
      printf '%s\n' "set HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install helper-scripts" >&2
      exit 1
   fi
done

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "  ok: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "  NOT OK: $1" >&2; }

## Run the real script as `bash <script>` (shebang -e ignored) with a
## HELPER_SCRIPTS_PATH that cannot resolve check_runtime.bsh, so the top-level
## source fails. A correctly-guarded script aborts non-zero; the pre-fix silent
## path would exit 0.
broken_path='/nonexistent-helper-scripts-xyz'
for subject in "${subjects[@]}"; do
   name="$(basename -- "${subject}")"
   rc=0
   err="$(HELPER_SCRIPTS_PATH="${broken_path}" bash "${subject}" 2>&1 >/dev/null)" || rc="$?"

   if [ "${rc}" -ne 0 ]; then
      ok "${name}: fails loudly (rc=${rc}) when check_runtime.bsh cannot be sourced"
   else
      notok "${name}: SILENT exit 0 under broken HELPER_SCRIPTS_PATH -- the source guard is missing"
   fi

   ## The failure must name the unresolved helper, not die obscurely later.
   if [[ "${err}" == *check_runtime* ]]; then
      ok "${name}: error output names check_runtime.bsh"
   else
      notok "${name}: expected a check_runtime.bsh error, got: '${err}'"
   fi
done

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
