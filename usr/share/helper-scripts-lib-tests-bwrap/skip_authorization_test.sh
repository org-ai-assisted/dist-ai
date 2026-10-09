#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins the bwrap skip policy of this sub-suite:
##  - every bwrap case, run with an UNUSABLE bwrap, is FATAL (exit 1) unless
##    DIST_AI_SKIP_AUTHORIZED=1, and then env-unmet (exit 78) -- never a silent
##    unauthorized skip;
##  - no bwrap-dependent case remains in the strict parent suite
##    (helper-scripts-lib-tests), whose skips CI does not authorize.
## Runs the REAL cases; only bwrap itself is replaced, by a PATH stub that fails
## the way bwrap does without unprivileged user namespaces.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
parent_dir="${script_dir}/../helper-scripts-lib-tests"

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "  ok: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "  NOT OK: $1" >&2; }

stub_dir="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${stub_dir}"
}
trap cleanup EXIT
printf '%s\n' '#!/bin/sh' 'echo "bwrap: No permissions to create new namespace" >&2' 'exit 1' > "${stub_dir}/bwrap"
chmod +x -- "${stub_dir}/bwrap"

shopt -s nullglob
bwrap_cases=( "${script_dir}"/use_leaprun_*_test.sh )
shopt -u nullglob
if [ "${#bwrap_cases[@]}" -eq 0 ]; then
   printf '%s\n' "FATAL: no bwrap cases found in '${script_dir}'" >&2
   exit 1
fi

for case_script in "${bwrap_cases[@]}"; do
   name="$(basename -- "${case_script}")"
   ## rc 1 alone could come from an earlier guard (e.g. subject unreadable);
   ## require bwrap_require's own FATAL line so the gate is what fired.
   rc=0
   stderr_text="$(env --unset=DIST_AI_SKIP_AUTHORIZED PATH="${stub_dir}:${PATH}" \
      "${case_script}" 2>&1 >/dev/null)" || rc=$?
   if [ "${rc}" -eq 1 ] && [[ "${stderr_text}" == *'FATAL: unprivileged bwrap sandbox unavailable and the skip is not authorized'* ]]; then
      ok "${name}: unusable bwrap, unauthorized -> FATAL (1) from bwrap_require"
   else
      notok "${name}: unusable bwrap, unauthorized exited ${rc}, expected 1 from bwrap_require; stderr: ${stderr_text}"
   fi
   rc=0
   env DIST_AI_SKIP_AUTHORIZED=1 PATH="${stub_dir}:${PATH}" \
      "${case_script}" >/dev/null 2>&1 || rc=$?
   if [ "${rc}" -eq 78 ]; then
      ok "${name}: unusable bwrap, authorized -> env-unmet (78)"
   else
      notok "${name}: unusable bwrap, authorized exited ${rc}, expected 78"
   fi
done

## A bwrap case left in (or added to) the parent suite would skip under its
## blanket-free CI config -- or, if someone re-authorized the parent, hide every
## other library case's skip behind it.
shopt -s nullglob
parent_cases=( "${parent_dir}"/*_test.sh )
shopt -u nullglob
strays=''
if [ "${#parent_cases[@]}" -gt 0 ]; then
   strays="$(grep --files-with-matches --fixed-strings --regexp='bwrap' -- "${parent_cases[@]}" || true)"
fi
if [ -z "${strays}" ]; then
   ok "no bwrap-dependent case in helper-scripts-lib-tests"
else
   notok "bwrap-dependent case(s) in the strict parent suite: ${strays}"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
