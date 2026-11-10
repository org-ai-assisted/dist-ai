#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Gate: no shell script in derivative-maker CALLS a library function without
## DIRECTLY SOURCING the file that defines it (project rule: "needs xyz -> source
## xyz", no transitive reliance). This is the has.bsh-in-5200_prepare-release
## class: a function reachable via no source path hits command-not-found at
## runtime. Detection is shfmt-AST based (never regex) in source_imports_check.py;
## known-unfixed top-level breaks live in source_imports_allowlist.txt and the
## gate fails on any new break or any stale allowlist entry.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")"
checker="${test_dir}/source_imports_check.py"
allowlist="${test_dir}/source_imports_allowlist.txt"

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

if [ ! -x "${checker}" ] || [ ! -r "${allowlist}" ]; then
   printf '%s\n' "FATAL: checker or allowlist not found next to ${BASH_SOURCE[0]}" >&2
   exit 1
fi

pass_count=0
fail_count=0

## --- real tree: every top-level break must be allowlisted, no stale entries ---
real_rc=0
"${checker}" "${dm_checkout}" "${allowlist}" || real_rc="$?"
if [ "${real_rc}" -eq 0 ]; then
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: source-imports gate clean (top-level breaks allowlisted)"
else
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: source-imports gate (exit ${real_rc}); see findings above" >&2
fi

## --- canary: an unallowlisted top-level break MUST fail the checker ----------
canary_dir="$(mktemp --directory)"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${canary_dir}"
}
trap cleanup EXIT
mkdir --parents \
   "${canary_dir}/packages/kicksecure/helper-scripts/usr/libexec/helper-scripts" \
   "${canary_dir}/build-steps.d"
hb="${canary_dir}/packages/kicksecure/helper-scripts/usr/libexec/helper-scripts/has.bsh"
# shellcheck disable=SC2016  # literal shell written into a fixture, not expanded here
printf '%s\n' '#!/bin/bash' 'has() { command -v -- "$1" >/dev/null 2>&1; }' > "${hb}"
## a clean consumer that DOES source has.bsh -- makes has.bsh an importable
## library (so `has` enters the vocabulary) and is itself not a break
# shellcheck disable=SC2016  # literal shell written into a fixture, not expanded here
printf '%s\n' '#!/bin/bash' \
   'source "${HELPER_SCRIPTS_PATH:-}"/usr/libexec/helper-scripts/has.bsh' \
   'if has sq; then true; fi' > "${canary_dir}/build-steps.d/98_canary_good"
## the break: calls has, never sources has.bsh
# shellcheck disable=SC2016  # literal shell written into a fixture, not expanded here
printf '%s\n' '#!/bin/bash' 'if has sq; then true; fi' \
   > "${canary_dir}/build-steps.d/99_canary_break"

canary_rc=0
"${checker}" "${canary_dir}" /dev/null >/dev/null 2>&1 || canary_rc="$?"
if [ "${canary_rc}" -eq 1 ]; then
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: canary -- checker flags an unallowlisted top-level break"
else
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: canary -- checker rc ${canary_rc}, expected 1" >&2
fi

printf '%s\n' "===== source-imports: ${pass_count} pass, ${fail_count} fail ====="
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
